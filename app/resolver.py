"""离线权威解析器。

在单份区域数据上模拟权威服务器对任意 (名称, 类型) 查询的应答：

* 切点（非顶点 NS）返回 referral（终止原因 ``delegation``，权威位为假）；
* 精确名称存在但无该类型时返回 NODATA（``noerror_nodata``）；
* 名称存在性按区域树判定：拥有 RRset 或拥有持 RRset 后代的节点
  （空非终结点）存在，返回 ``ent_nodata``；其余名称（包括存在节点的
  叶子下级）不存在，返回 ``nxdomain``；
* 通配符按 RFC 4592 的“最近包围名 / 合成源”规则扩展：合成源为
  ``*.<最近存在包围名>``，任意深度的未列名都可命中；更近的存在节点
  （含空非终结点）会成为包围名，从而阻断上层通配；
* CNAME 与 DNAME 逐跳重判，DNAME 按 RFC 6672 合成 CNAME；
* 别名环只标记（``alias_loop``），不联网、不递归。

dnspython 的 ``Name.labels`` 与区域文本同序（最左标签在下标 0，根的空
标签在末尾）。
"""
from __future__ import annotations

from dataclasses import dataclass, field

import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rdata

from .zone import ParsedZone, RR

MAX_ALIAS_HOPS = 32

TERMINATIONS = (
    "exact",
    "wildcard_expansion",
    "delegation",
    "noerror_nodata",
    "ent_nodata",
    "nxdomain",
    "alias_loop",
    "alias_chain_limit",
)


@dataclass
class Hop:
    """别名链上的一跳（CNAME 或 DNAME 合成）。"""

    kind: str  # CNAME / WILDCARD_CNAME / DNAME / WILDCARD_DNAME
    owner: dns.name.Name          # 真实属主（通配符时为 *.x，DNAME 时为祖先）
    target: dns.name.Name         # 本跳指向的名称
    cname_owner: dns.name.Name    # 线上应答里 CNAME 的属主（DNAME 时为合成名）
    cname_rr: RR | None = None    # 真实 CNAME RR；DNAME 合成时为 None
    dname_rr: RR | None = None    # 真实（或按 RFC6672 呈现的）DNAME RR


@dataclass
class Answer:
    qname: dns.name.Name
    qtype: int
    rcode: str               # NOERROR / NXDOMAIN
    aa: bool
    termination: str
    answer: list[RR] = field(default_factory=list)
    authority: list[RR] = field(default_factory=list)
    additional: list[RR] = field(default_factory=list)
    hops: list[Hop] = field(default_factory=list)
    # 真正产生数据的通配符属主（如 *.wild.example.）
    wildcard_source: dns.name.Name | None = None
    # 触发 DNAME 改写的最近祖先名
    dname_encloser: dns.name.Name | None = None


class Resolver:
    def __init__(self, pz: ParsedZone):
        self.pz = pz
        self.origin = pz.origin
        self.cuts = sorted(
            (
                owner
                for owner, types in pz.rrsets.items()
                if owner != self.origin and dns.rdatatype.NS in types
            ),
            key=lambda n: (len(n.labels), n),
        )

    # ------------------------------------------------------------------ utils
    def _soa_rrset(self) -> list[RR]:
        # 否定应答（NODATA/NXDOMAIN）的 SOA 权威记录属主始终是区域顶点。
        soa = self.pz.soa
        return [RR(owner=self.origin, rdtype=dns.rdatatype.SOA,
                   ttl=soa.ttl, rdata=soa.rdata)]

    def _find_cut(self, qname: dns.name.Name) -> dns.name.Name | None:
        """qname 所在的最近切点（切点本身及其以下全部移交）。"""
        best: dns.name.Name | None = None
        for cut in self.cuts:
            if qname.is_subdomain(cut) and (
                best is None or cut.is_subdomain(best)
            ):
                best = cut
        return best

    def _make_cname_rr(self, owner: dns.name.Name,
                       target: dns.name.Name, ttl: int) -> RR:
        rdata = dns.rdata.from_text(
            dns.rdataclass.IN, dns.rdatatype.CNAME, target.to_text()
        )
        return RR(owner=owner, rdtype=dns.rdatatype.CNAME,
                  ttl=ttl, rdata=rdata)

    def _closest_encloser(self, qname: dns.name.Name) -> dns.name.Name:
        """qname 的最近存在包围名（含 qname 自身）。

        “存在”＝拥有 RRset，或为空非终结点（有后代持有 RRset）。
        区域顶点恒存在，上溯必然终止。
        """
        cur = qname
        while not self.pz.exists_name(cur):
            cur = cur.parent()
        return cur

    def _nearest_dname_owner(
            self, start: dns.name.Name) -> dns.name.Name | None:
        """自 start 向上最近一个持有 DNAME 的节点（DNAME 改写整个子树）。"""
        cur = start
        while True:
            if dns.rdatatype.DNAME in self.pz.rdatasets(cur):
                return cur
            if cur == self.origin:
                return None
            cur = cur.parent()

    # ------------------------------------------------------------------ core
    def _referral(self, qname: dns.name.Name, qtype: int,
                  cut: dns.name.Name) -> Answer:
        ns_rrs = list(self.pz.rrsets[cut][dns.rdatatype.NS])
        additional: list[RR] = []
        for rr in ns_rrs:
            types = self.pz.rdatasets(rr.rdata.target)
            for rt in (dns.rdatatype.A, dns.rdatatype.AAAA):
                if rt in types:
                    additional.extend(types[rt])
        return Answer(
            qname=qname, qtype=qtype, rcode="NOERROR", aa=False,
            termination="delegation",
            authority=ns_rrs, additional=additional,
        )

    def _wildcard_dname(self, qname, qtype, wildcard_name, wc_types, encloser):
        dname_rr = wc_types[dns.rdatatype.DNAME][0]
        target = dname_rr.rdata.target
        # 设 qname 相对合成源父节点为 L1.L2...Ln.P（n>=1）。
        # RFC 6672 3.1.3：单层（n=1）整体替换为 target；
        # 多层时仅最左标签 L1 被 DNAME 吞掉，其余 L2...Ln 保留，
        # 合成 CNAME 指向 L2...Ln.target。
        rel = qname.relativize(encloser)
        first = dns.name.from_text(rel.labels[0].decode(), origin=encloser)
        if len(rel.labels) == 1:
            new_name = target
        else:
            new_name = dns.name.Name(rel.labels[1:] + target.labels)
        synth_cname = self._make_cname_rr(qname, new_name, dname_rr.ttl)
        presented_dname = RR(
            owner=first, rdtype=dns.rdatatype.DNAME,
            ttl=dname_rr.ttl, rdata=dname_rr.rdata,
        )
        hop = Hop(
            kind="WILDCARD_DNAME", owner=wildcard_name, target=new_name,
            cname_owner=qname, dname_rr=presented_dname,
        )
        ans = Answer(
            qname=qname, qtype=qtype, rcode="NOERROR", aa=True,
            termination="wildcard_expansion",
            answer=[synth_cname, presented_dname],
            wildcard_source=wildcard_name,
        )
        return ans, hop

    def _exact_dname(self, qname, qtype, encloser, dn_types):
        dname_rr = dn_types[dns.rdatatype.DNAME][0]
        new_name = qname.relativize(encloser).concatenate(dname_rr.rdata.target)
        synth_cname = self._make_cname_rr(qname, new_name, dname_rr.ttl)
        hop = Hop(
            kind="DNAME", owner=encloser, target=new_name,
            cname_owner=qname, dname_rr=dname_rr,
        )
        ans = Answer(
            qname=qname, qtype=qtype, rcode="NOERROR", aa=True,
            termination="exact", answer=[synth_cname, dname_rr],
            dname_encloser=encloser,
        )
        return ans, hop

    def _lookup(self, qname: dns.name.Name,
                qtype: int) -> tuple[Answer, Hop | None]:
        # 1) 切点优先（含切点本身与其以下的任何名称）。
        cut = self._find_cut(qname)
        if cut is not None:
            return self._referral(qname, qtype, cut), None

        types = self.pz.rdatasets(qname)

        # 2) 精确节点。
        if types:
            if (dns.rdatatype.CNAME in types
                    and qtype != dns.rdatatype.CNAME):
                cname_rr = types[dns.rdatatype.CNAME][0]
                hop = Hop(
                    kind="CNAME", owner=qname,
                    target=cname_rr.rdata.target,
                    cname_owner=qname, cname_rr=cname_rr,
                )
                ans = Answer(
                    qname=qname, qtype=qtype, rcode="NOERROR", aa=True,
                    termination="exact", answer=[cname_rr],
                )
                return ans, hop

            if qtype in types:
                ans = Answer(
                    qname=qname, qtype=qtype, rcode="NOERROR", aa=True,
                    termination="exact", answer=list(types[qtype]),
                )
                return ans, None

            # 精确名存在但无该类型；DNAME 仅对严格下级名生效，精确名不合成。
            ans = Answer(
                qname=qname, qtype=qtype, rcode="NOERROR", aa=True,
                termination="noerror_nodata",
                authority=self._soa_rrset(),
            )
            return ans, None

        # 3) 名称无 RRset：最近存在包围名决定通配源、DNAME 与存在性。
        encloser = self._closest_encloser(qname)

        # 3a) qname 不存在时，合成源为 *.encloser（RFC 4592）：任意深度
        #     的未列名都可命中，只要中间没有更近的存在节点阻断——存在性
        #     闭包已保证 encloser 与 qname 之间不存在任何节点。
        if encloser != qname:
            wildcard_name = dns.name.Name([b"*"]).concatenate(encloser)
            if self.pz.has(wildcard_name):
                wc_types = self.pz.rdatasets(wildcard_name)
                if (dns.rdatatype.CNAME in wc_types
                        and qtype != dns.rdatatype.CNAME):
                    cname_rr = wc_types[dns.rdatatype.CNAME][0]
                    synthetic = self._make_cname_rr(
                        qname, cname_rr.rdata.target, cname_rr.ttl
                    )
                    hop = Hop(
                        kind="WILDCARD_CNAME", owner=wildcard_name,
                        target=cname_rr.rdata.target,
                        cname_owner=qname, cname_rr=cname_rr,
                    )
                    ans = Answer(
                        qname=qname, qtype=qtype, rcode="NOERROR", aa=True,
                        termination="wildcard_expansion",
                        answer=[synthetic], wildcard_source=wildcard_name,
                    )
                    return ans, hop

                if dns.rdatatype.DNAME in wc_types:
                    return self._wildcard_dname(
                        qname, qtype, wildcard_name, wc_types, encloser
                    )

                if qtype in wc_types:
                    rrs = [
                        RR(owner=qname, rdtype=rr.rdtype,
                           ttl=rr.ttl, rdata=rr.rdata)
                        for rr in wc_types[qtype]
                    ]
                    ans = Answer(
                        qname=qname, qtype=qtype, rcode="NOERROR", aa=True,
                        termination="wildcard_expansion",
                        answer=rrs, wildcard_source=wildcard_name,
                    )
                    return ans, None

                ans = Answer(
                    qname=qname, qtype=qtype, rcode="NOERROR", aa=True,
                    termination="noerror_nodata",
                    authority=self._soa_rrset(),
                    wildcard_source=wildcard_name,
                )
                return ans, None

        # 3b) 自包围名向上最近的 DNAME 改写 qname（严格下级名合成；
        #     qname 自身无 RRset，即便它是空非终结点也不会命中自身）。
        dn_owner = self._nearest_dname_owner(encloser)
        if dn_owner is not None:
            return self._exact_dname(
                qname, qtype, dn_owner, self.pz.rdatasets(dn_owner)
            )

        # 3c) qname 自身存在（空非终结点）→ NODATA；否则 NXDOMAIN。
        #     叶子下级不在存在性闭包内，不会仅凭父节点有数据而误判存在。
        if encloser == qname:
            ans = Answer(
                qname=qname, qtype=qtype, rcode="NOERROR", aa=True,
                termination="ent_nodata",
                authority=self._soa_rrset(),
            )
            return ans, None

        ans = Answer(
            qname=qname, qtype=qtype, rcode="NXDOMAIN", aa=True,
            termination="nxdomain",
            authority=self._soa_rrset(),
        )
        return ans, None

    # ---------------------------------------------------------------- public
    def resolve(self, qname: dns.name.Name, qtype: int) -> Answer:
        if not qname.is_subdomain(self.origin):
            raise ValueError(f"查询名 {qname} 不在区域 {self.origin} 内")

        cur_name, cur_type = qname, qtype
        hops: list[Hop] = []
        wildcard_sources: list[dns.name.Name] = []
        dname_enclosers: list[dns.name.Name] = []
        seen: set[tuple[dns.name.Name, int, dns.name.Name]] = set()

        while True:
            ans, hop = self._lookup(cur_name, cur_type)
            if hop is None:
                final = ans
                break

            hops.append(hop)
            if hop.kind in ("DNAME", "WILDCARD_DNAME"):
                dname_enclosers.append(hop.owner)
            if hop.kind in ("WILDCARD_CNAME", "WILDCARD_DNAME"):
                wildcard_sources.append(hop.owner)

            state = (cur_name, cur_type, hop.target)
            if state in seen:
                chain = self._chain_answer(qname, qtype, hops)
                chain.termination = "alias_loop"
                self._annotate(chain, wildcard_sources, dname_enclosers)
                return chain
            seen.add(state)

            if len(hops) >= MAX_ALIAS_HOPS:
                chain = self._chain_answer(qname, qtype, hops)
                chain.termination = "alias_chain_limit"
                self._annotate(chain, wildcard_sources, dname_enclosers)
                return chain

            cur_name = hop.target

        chain = self._chain_answer(qname, qtype, hops)
        chain.rcode = final.rcode
        chain.aa = final.aa
        chain.termination = final.termination
        chain.authority = final.authority
        chain.additional = final.additional
        chain.answer = chain.answer + final.answer
        # 别名链末端若为 NODATA/NXDOMAIN/referral，保留其终止原因；
        # 若链中发生过通配/DNAME 改写而末端是普通命中，仍标注改写来源。
        self._annotate(chain, wildcard_sources, dname_enclosers)
        if final.wildcard_source is not None:
            chain.wildcard_source = final.wildcard_source
        if final.dname_encloser is not None:
            chain.dname_encloser = final.dname_encloser
        return chain

    @staticmethod
    def _annotate(chain, wildcard_sources, dname_enclosers):
        if wildcard_sources:
            chain.wildcard_source = wildcard_sources[-1]
        if dname_enclosers:
            chain.dname_encloser = dname_enclosers[-1]

    def _chain_answer(self, qname, qtype, hops: list[Hop]) -> Answer:
        answer: list[RR] = []
        for hop in hops:
            if hop.kind in ("CNAME",):
                answer.append(hop.cname_rr)
            elif hop.kind == "WILDCARD_CNAME":
                answer.append(self._make_cname_rr(
                    hop.cname_owner, hop.target, hop.cname_rr.ttl
                ))
            else:  # DNAME / WILDCARD_DNAME：线上为 [合成 CNAME, DNAME]
                answer.append(self._make_cname_rr(
                    hop.cname_owner, hop.target, hop.dname_rr.ttl
                ))
                answer.append(hop.dname_rr)
        return Answer(
            qname=qname, qtype=qtype, rcode="NOERROR", aa=True,
            termination="exact", answer=answer, hops=list(hops),
        )
