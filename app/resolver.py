"""离线权威解析器。

在单份区域数据上模拟权威服务器对任意 (名称, 类型) 查询的应答：

* 切点（非顶点 NS）返回 referral（终止原因 ``delegation``，权威位为假）；
* 精确名称存在但无该类型时返回 NODATA（``noerror_nodata``）；
* 名称不存在时区分 NXDOMAIN 与空非终结点 NODATA（``ent_nodata``）；
* 最近祖先通配符按 RFC 4592 的“源即合点（closest encloser / source of
  synthesis）”规则扩展；
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
    @staticmethod
    def _is_wildcard(name: dns.name.Name) -> bool:
        return len(name.labels) >= 2 and name.labels[0] == b"*"

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

    def _find_source(self, qname: dns.name.Name):
        """定位最长真实包围名与通配合成源。

        返回六元组：
        ``(wildcard_name, wildcard_types, nearest_real, has_real_ancestor,
        star_candidate, star_parent)``。

        * ``wildcard_name`` 非空时是 RFC 4592 直接通配扩展；
        * ``star_candidate`` 非空但 ``wildcard_name`` 为空时，说明存在一个
          更深的通配符节点，其下级为 DNAME 时按 RFC 6672 3.1.3 合成
          （``star_parent`` 即该通配符去掉 ``*`` 后的父名）。
        """
        nearest_real = self.origin
        star_candidate: dns.name.Name | None = None
        star_parent: dns.name.Name | None = None

        cur = qname.parent()
        while True:
            if star_candidate is None:
                cand = dns.name.Name([b"*"]).concatenate(cur)
                if self.pz.has(cand):
                    star_candidate = cand
                    star_parent = cur
            if self.pz.has(cur) and not self._is_wildcard(cur):
                nearest_real = cur
                break
            if cur == self.origin:
                break
            cur = cur.parent()

        wildcard_name = None
        wildcard_types = None
        # RFC 4592：最深候选通配符 *.P 的父节点 P 恰为 qname 的父节点时，
        # 通配合成生效（与 P 自身是否有非通配数据无关）。
        if star_candidate is not None and star_parent == qname.parent():
            wildcard_name = star_candidate
            wildcard_types = self.pz.rdatasets(star_candidate)

        has_real_ancestor = nearest_real != self.origin
        return (wildcard_name, wildcard_types, nearest_real,
                has_real_ancestor, star_candidate, star_parent)

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

        # 3) 名称不存在：定位通配合成源与最近真实包围名。
        (wildcard_name, wc_types, encloser, has_real_ancestor,
         star_candidate, star_parent) = self._find_source(qname)

        # 3a) 最近祖先通配符（RFC 4592 直接通配）。
        if wc_types is not None:
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

        # 3a') 深层通配符节点：只有 DNAME 能覆盖（RFC 6672 3.1.3）。
        if (wc_types is None and star_candidate is not None
                and dns.rdatatype.DNAME
                in self.pz.rdatasets(star_candidate)):
            wc_dn_types = self.pz.rdatasets(star_candidate)
            return self._wildcard_dname(
                qname, qtype, star_candidate, wc_dn_types, star_parent
            )

        # 3b) 最近真实祖先上的精确 DNAME，仅对严格下级名合成。
        dn_types = self.pz.rdatasets(encloser)
        if dns.rdatatype.DNAME in dn_types and qname != encloser:
            return self._exact_dname(qname, qtype, encloser, dn_types)

        # 3c) 路径上有真实节点 → 空非终结点 NODATA；否则 NXDOMAIN。
        if has_real_ancestor:
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
