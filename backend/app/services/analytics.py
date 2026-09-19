"""
Derived analytics: compliance coverage, attack paths, and category risk.

Everything here is computed from the findings and assets a scan actually
produced. Nothing is a stored constant, so when findings change -- a connector
is added, a fix is applied -- these move with them.
"""
import logging
import re
from typing import Any, Dict, List, Optional

from app.db.models import Asset, Finding

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Compliance
# ---------------------------------------------------------------------------
# Each framework lists the controls this platform can speak to from external
# discovery plus connector data. Coverage is the share of those controls with
# no failing finding against them -- deliberately not a claim of full
# framework compliance, which needs evidence this platform never sees
# (policies, training records, contracts, physical controls).

FRAMEWORKS: Dict[str, Dict[str, Any]] = {
    "NIST CSF": {
        "full_name": "NIST Cybersecurity Framework 2.0",
        "controls": {
            "PR.AA-01": {"name": "Identities and credentials are managed", "categories": ["Identity"]},
            "PR.AA-05": {"name": "Access permissions incorporate least privilege", "categories": ["Identity", "Cloud"]},
            "PR.PS-02": {"name": "Software is maintained and patched", "categories": ["Web App", "Network"]},
            "PR.IR-01": {"name": "Networks and environments are protected", "categories": ["Network"]},
            "PR.DS-02": {"name": "Data in transit is protected", "categories": ["Email", "Web App"]},
            "ID.AM-01": {"name": "Hardware and software inventory is maintained", "categories": ["__assets__"]},
            "DE.CM-01": {"name": "Networks are monitored to find adverse events", "categories": ["__siem__"]},
        },
    },
    "ISO 27001": {
        "full_name": "ISO/IEC 27001:2022 Annex A",
        "controls": {
            "A.5.15": {"name": "Access control", "categories": ["Identity"]},
            "A.5.17": {"name": "Authentication information", "categories": ["Identity", "Cloud"]},
            "A.8.8": {"name": "Management of technical vulnerabilities", "categories": ["Web App", "Network"]},
            "A.8.9": {"name": "Configuration management", "categories": ["Cloud", "Network"]},
            "A.8.12": {"name": "Data leakage prevention", "categories": ["Email", "Cloud"]},
            "A.5.9": {"name": "Inventory of information assets", "categories": ["__assets__"]},
            "A.8.16": {"name": "Monitoring activities", "categories": ["__siem__"]},
        },
    },
    "CIS Controls": {
        "full_name": "CIS Critical Security Controls v8",
        "controls": {
            "CIS 1": {"name": "Inventory of enterprise assets", "categories": ["__assets__"]},
            "CIS 4": {"name": "Secure configuration", "categories": ["Cloud", "Network"]},
            "CIS 5": {"name": "Account management", "categories": ["Identity"]},
            "CIS 6": {"name": "Access control management", "categories": ["Identity", "Cloud"]},
            "CIS 7": {"name": "Continuous vulnerability management", "categories": ["Web App", "Network"]},
            "CIS 8": {"name": "Audit log management", "categories": ["__siem__"]},
            "CIS 9": {"name": "Email and web browser protections", "categories": ["Email"]},
        },
    },
    "RBI Guidelines": {
        "full_name": "RBI Cyber Security Framework (regulated entities)",
        "controls": {
            "RBI-AC": {"name": "Access control and authentication", "categories": ["Identity"]},
            "RBI-PM": {"name": "Patch and vulnerability management", "categories": ["Web App", "Network"]},
            "RBI-NW": {"name": "Network perimeter protection", "categories": ["Network"]},
            "RBI-EM": {"name": "Anti-phishing and email security", "categories": ["Email"]},
            "RBI-IN": {"name": "Asset inventory and classification", "categories": ["__assets__"]},
            "RBI-MO": {"name": "Continuous surveillance and SOC", "categories": ["__siem__"]},
        },
    },
    "SEBI CSCRF": {
        "full_name": "SEBI Cybersecurity and Cyber Resilience Framework",
        "controls": {
            "CSCRF-ID": {"name": "Identify: asset and risk register", "categories": ["__assets__"]},
            "CSCRF-PR1": {"name": "Protect: identity and access", "categories": ["Identity", "Cloud"]},
            "CSCRF-PR2": {"name": "Protect: secure configuration", "categories": ["Cloud", "Network"]},
            "CSCRF-PR3": {"name": "Protect: email and data security", "categories": ["Email"]},
            "CSCRF-DE": {"name": "Detect: monitoring and logging", "categories": ["__siem__"]},
            "CSCRF-VA": {"name": "Vulnerability assessment cadence", "categories": ["Web App", "Network"]},
        },
    },
}

SEVERITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0}


def compute_compliance(
    findings: List[Finding],
    assets: Optional[List[Asset]] = None,
    connected_sources: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """
    Map findings onto framework controls and compute coverage per framework.

    A control fails if any finding in one of its categories is open. Two
    pseudo-categories capture things a finding list cannot express:

      __assets__  inventory controls, which fail while assets are unmonitored
      __siem__    monitoring controls, which cannot pass without log evidence
    """
    connected_sources = connected_sources or []
    assets = assets or []

    failing_categories = {f.category for f in findings}
    worst_by_category: Dict[str, str] = {}
    for f in findings:
        current = worst_by_category.get(f.category, "Unknown")
        if SEVERITY_RANK.get(f.severity, 0) > SEVERITY_RANK.get(current, 0):
            worst_by_category[f.category] = f.severity

    unmonitored = [a for a in assets if (a.status or "").lower() != "monitored"]
    inventory_fails = bool(unmonitored) or not assets
    monitoring_fails = "siem" not in connected_sources

    results: List[Dict[str, Any]] = []
    for name, spec in FRAMEWORKS.items():
        controls_out: List[Dict[str, Any]] = []
        met = 0
        for control_id, control in spec["controls"].items():
            cats = control["categories"]
            if "__assets__" in cats:
                failed = inventory_fails
                reason = (
                    f"{len(unmonitored)} asset(s) discovered but not monitored"
                    if unmonitored else "No asset inventory established"
                ) if failed else f"{len(assets)} asset(s) inventoried and monitored"
                severity = "High" if failed else None
            elif "__siem__" in cats:
                failed = monitoring_fails
                reason = ("No log or SIEM source connected, so monitoring cannot be evidenced"
                          if failed else "Log platform connected and supplying alert history")
                severity = "Medium" if failed else None
            else:
                hit = [c for c in cats if c in failing_categories]
                failed = bool(hit)
                severity = max((worst_by_category[c] for c in hit),
                               key=lambda s: SEVERITY_RANK.get(s, 0)) if hit else None
                reason = (f"Open {', '.join(hit)} finding(s)" if failed
                          else f"No open findings in {', '.join(cats)}")

            if not failed:
                met += 1
            controls_out.append({
                "id": control_id,
                "name": control["name"],
                "met": not failed,
                "severity": severity,
                "reason": reason,
            })

        total = len(controls_out)
        results.append({
            "name": name,
            "full_name": spec["full_name"],
            "coverage": round(100 * met / total) if total else 0,
            "controls_met": met,
            "controls_total": total,
            "controls": controls_out,
        })

    return results


# ---------------------------------------------------------------------------
# Attack paths
# ---------------------------------------------------------------------------

# How a finding category behaves in a chain. `pivot` findings are the ones
# that turn access into deeper access, which is what makes them breakpoints.
CATEGORY_ROLE = {
    "Web App": {"stage": "entry", "icon": "Bug", "mitre": ("T1190", "Exploit Public-Facing Application")},
    "Network": {"stage": "entry", "icon": "Server", "mitre": ("T1021", "Remote Services")},
    "Email": {"stage": "entry", "icon": "Mail", "mitre": ("T1566", "Phishing")},
    "Identity": {"stage": "pivot", "icon": "KeyRound", "mitre": ("T1078", "Valid Accounts")},
    "Cloud": {"stage": "pivot", "icon": "Cloud", "mitre": ("T1530", "Data from Cloud Storage")},
}

CROWN_JEWEL_BY_CATEGORY = {
    "Web App": ("Customer Database", "Crown jewel asset"),
    "Network": ("File Server", "Shared documents"),
    "Email": ("Mailboxes", "Business correspondence"),
    "Identity": ("Admin Panel", "Full write access"),
    "Cloud": ("Object Storage", "Customer records"),
}


SOURCE_BY_CATEGORY = {
    "Email": ("src:phish", "Phishing Email", "Employee inbox", "Mail"),
}
DEFAULT_SOURCE = ("src:internet", "Internet", "Anonymous access", "Globe")


def _path_eal(chain: List[Finding]) -> float:
    """
    Expected loss for one chain.

    Combined as a probabilistic union over the chain's risk scores rather
    than a sum, matching how compute_org_score aggregates, then floored at
    the single largest step loss so a chain is never worth less than its
    worst link.
    """
    if not chain:
        return 0.0
    residual = 1.0
    for f in chain:
        residual *= (1.0 - min(max((f.final_risk_score or 0.0), 0.0), 0.99))
    total = sum(f.eal or 0 for f in chain)
    return round(total * (1.0 - residual) + max((f.eal or 0) for f in chain), 1)


def compute_attack_graph(
    findings: List[Finding],
    assets: Optional[List[Asset]] = None,
    max_paths: int = 6,
) -> Dict[str, Any]:
    """
    Build a real attack graph over the findings a scan produced.

    Structure is a four-layer DAG:

        source -> entry finding -> pivot finding (optional) -> crown jewel

    Entry-stage findings (web, network, email) give initial access; pivot
    stage findings (identity, cloud) turn that access into deeper access.
    Every entry is wired to every pivot, because an attacker who is inside
    can reach any weak escalation path, not just one pre-chosen for them.
    The result is a genuine converging graph rather than a fan of
    independent lines.

    The choke point is then computed rather than assumed: for each finding
    node, sum the expected loss of every path that traverses it, and take
    the node carrying the most severable loss (ties broken by the cheaper
    fix). Removing that node cuts every path through it, which is what makes
    it the single highest-leverage fix. Nothing here is hardcoded -- with a
    different finding set, a different node wins.
    """
    assets = assets or []
    asset_names = {a.id: a.asset_name for a in assets}

    entries = [f for f in findings if CATEGORY_ROLE.get(f.category, {}).get("stage") == "entry"]
    pivots = [f for f in findings if CATEGORY_ROLE.get(f.category, {}).get("stage") == "pivot"]

    if not entries and not pivots:
        return {"nodes": [], "edges": [], "paths": [], "choke_point": None}

    # An identity or cloud weakness with no external entry is still reachable
    # -- credential stuffing and public buckets need no prior foothold -- so
    # promote pivots to entries when nothing else gets an attacker in.
    promoted = not entries
    if promoted:
        entries = list(pivots)
        pivots = []

    entries.sort(key=lambda f: (f.eal or 0, SEVERITY_RANK.get(f.severity, 0)), reverse=True)
    pivots.sort(key=lambda f: (f.eal or 0, f.reduction or 0), reverse=True)

    entries = entries[:max_paths]
    pivots = pivots[:3]

    nodes: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, str]] = []
    seen_edges = set()

    def add_node(node_id: str, **attrs) -> str:
        if node_id not in nodes:
            nodes[node_id] = {"id": node_id, **attrs}
        return node_id

    def add_edge(a: str, b: str) -> None:
        if (a, b) not in seen_edges:
            seen_edges.add((a, b))
            edges.append({"source": a, "target": b})

    def finding_node(f: Finding, kind: str) -> str:
        role = CATEGORY_ROLE.get(f.category, CATEGORY_ROLE["Network"])
        return add_node(
            f"f:{f.id}",
            kind=kind,
            label=f.short,
            sub=f.cve_id or asset_names.get(f.asset_id, "external asset"),
            icon=role["icon"],
            category=f.category,
            finding_id=f.id,
            severity=f.severity,
            eal=round(f.eal or 0, 1),
            cost=f.cost or 0,
            reduction=f.reduction or 0,
            mitre_id=role["mitre"][0],
            mitre_name=role["mitre"][1],
        )

    # --- Build the graph ------------------------------------------------
    raw_paths: List[Dict[str, Any]] = []
    for entry in entries:
        src_id, src_label, src_sub, src_icon = SOURCE_BY_CATEGORY.get(
            entry.category, DEFAULT_SOURCE
        )
        add_node(src_id, kind="source", label=src_label, sub=src_sub, icon=src_icon)
        entry_id = finding_node(entry, "entry")
        add_edge(src_id, entry_id)

        # Pivots this entry can reach (all of them, minus itself).
        reachable = [p for p in pivots if p.id != entry.id]

        if reachable:
            for pivot in reachable:
                pivot_id = finding_node(pivot, "pivot")
                add_edge(entry_id, pivot_id)

                jewel, jewel_sub = CROWN_JEWEL_BY_CATEGORY.get(
                    pivot.category, ("Business Systems", "Core operations")
                )
                target_id = add_node(
                    f"t:{jewel}", kind="target", label=jewel, sub=jewel_sub, icon="Shield"
                )
                add_edge(pivot_id, target_id)

                raw_paths.append({
                    "chain": [entry, pivot],
                    "node_ids": [src_id, entry_id, pivot_id, target_id],
                    "target": jewel,
                })
        else:
            jewel, jewel_sub = CROWN_JEWEL_BY_CATEGORY.get(
                entry.category, ("Business Systems", "Core operations")
            )
            target_id = add_node(
                f"t:{jewel}", kind="target", label=jewel, sub=jewel_sub, icon="Shield"
            )
            add_edge(entry_id, target_id)
            raw_paths.append({
                "chain": [entry],
                "node_ids": [src_id, entry_id, target_id],
                "target": jewel,
            })

    # --- Score the paths --------------------------------------------------
    for p in raw_paths:
        p["eal"] = _path_eal(p["chain"])
    raw_paths.sort(key=lambda p: p["eal"], reverse=True)
    raw_paths = raw_paths[:max_paths]

    # --- Choke-point analysis --------------------------------------------
    # How much expected loss does removing each finding node actually cut?
    # Losses across overlapping paths cannot be summed -- a finding shared by
    # two paths would have its loss counted twice -- so a node is measured by
    # how many paths it sits on, with the worst single path breaking ties.
    severed_worst: Dict[str, float] = {}
    severed_count: Dict[str, int] = {}
    for p in raw_paths:
        for f in p["chain"]:
            key = f"f:{f.id}"
            severed_worst[key] = max(severed_worst.get(key, 0.0), p["eal"])
            severed_count[key] = severed_count.get(key, 0) + 1

    choke_id: Optional[str] = None
    if severed_count:
        choke_id = max(
            severed_count,
            key=lambda k: (
                severed_count[k],
                severed_worst[k],
                -(nodes[k].get("cost") or 0),
            ),
        )

    # --- Emit paths in display shape --------------------------------------
    out_paths: List[Dict[str, Any]] = []
    for p in raw_paths:
        chain: List[Finding] = p["chain"]
        # A path not crossing the global choke point still has a local one:
        # its own highest-leverage link.
        local_break = None
        if choke_id and any(f"f:{f.id}" == choke_id for f in chain):
            local_break = choke_id
        else:
            best = max(chain, key=lambda f: ((f.reduction or 0), -(f.cost or 0)))
            local_break = f"f:{best.id}"

        fix_node = nodes[local_break]
        fix_cost = fix_node.get("cost") or 0
        eal = p["eal"]
        rosi = None if fix_cost == 0 else round(((eal * 100000) - fix_cost) / fix_cost * 100)

        mitre_seen, mitre = set(), []
        for f in chain:
            role = CATEGORY_ROLE.get(f.category, CATEGORY_ROLE["Network"])
            if role["mitre"][0] not in mitre_seen:
                mitre_seen.add(role["mitre"][0])
                mitre.append({"id": role["mitre"][0], "name": role["mitre"][1]})

        out_paths.append({
            "id": chain[0].id,
            "label": f"{chain[0].category} to {p['target']}",
            "node_ids": p["node_ids"],
            "eal": eal,
            "mitre": mitre,
            "fix": fix_node.get("label"),
            "fix_cost": fix_cost,
            "rosi": rosi,
            "breakpoint_node_id": local_break,
        })

    # Mark the graph's choke point on the node itself so the renderer does
    # not have to re-derive it.
    for node_id, node in nodes.items():
        node["is_choke_point"] = node_id == choke_id
        node["severed_paths"] = severed_count.get(node_id, 0)
        node["severed_eal"] = round(severed_worst.get(node_id, 0.0), 1)

    choke_point = None
    if choke_id:
        node = nodes[choke_id]
        choke_point = {
            "node_id": choke_id,
            "finding_id": node.get("finding_id"),
            "label": node.get("label"),
            "cost": node.get("cost") or 0,
            "severed_paths": severed_count.get(choke_id, 0),
            "total_paths": len(out_paths),
            "severed_eal": round(severed_worst.get(choke_id, 0.0), 1),
        }

    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "paths": out_paths,
        "choke_point": choke_point,
    }


def compute_attack_paths(
    findings: List[Finding],
    assets: Optional[List[Asset]] = None,
    max_paths: int = 4,
) -> List[Dict[str, Any]]:
    """
    Attack chains in the flat step shape the path list renders.

    Derived from compute_attack_graph so the chain list and the graph can
    never disagree: same nodes, same breakpoint, same expected loss.
    """
    graph = compute_attack_graph(findings, assets, max_paths=max_paths)
    if not graph["paths"]:
        return []

    nodes = {n["id"]: n for n in graph["nodes"]}
    out: List[Dict[str, Any]] = []
    for p in graph["paths"]:
        steps = []
        for node_id in p["node_ids"]:
            n = nodes[node_id]
            steps.append({
                "title": n["label"],
                "sub": n.get("sub", ""),
                "icon": n.get("icon", "Server"),
                "breakpoint": node_id == p["breakpoint_node_id"],
            })
        out.append({
            "id": p["id"],
            "label": p["label"],
            "steps": steps,
            "eal": p["eal"],
            "mitre": p["mitre"],
            "fix": p["fix"],
            "fix_cost": p["fix_cost"],
            "rosi": p["rosi"],
        })
    return out


# ---------------------------------------------------------------------------
# Category risk (radar)
# ---------------------------------------------------------------------------

RADAR_CATEGORIES = ["Identity", "Network", "Web App", "Cloud", "Email"]


def compute_category_risk(findings: List[Finding]) -> List[Dict[str, Any]]:
    """
    Per-category residual risk on a 0-100 scale.

    A category with no findings scores 0. Otherwise the category's findings
    are combined as a probabilistic union, matching how the org score
    aggregates, so the radar and the headline number cannot disagree.
    """
    out: List[Dict[str, Any]] = []
    for category in RADAR_CATEGORIES:
        in_cat = [f for f in findings if f.category == category]
        if not in_cat:
            out.append({"category": category, "risk": 0, "findings": 0, "worst": None})
            continue
        residual = 1.0
        for f in in_cat:
            residual *= (1.0 - min(max(f.final_risk_score or 0.0, 0.0), 0.99))
        worst = max(in_cat, key=lambda f: SEVERITY_RANK.get(f.severity, 0)).severity
        out.append({
            "category": category,
            "risk": round(100 * (1.0 - residual)),
            "findings": len(in_cat),
            "worst": worst,
        })
    return out


# ---------------------------------------------------------------------------
# Insurance readiness
# ---------------------------------------------------------------------------
# Cyber insurance applications converge on a short list of controls: MFA on
# privileged accounts, managed endpoints with a patch cadence, security
# logging, email authentication, and a maintained asset inventory. Readiness
# is the share of those an underwriter could actually be shown evidence for.
#
# A control that cannot be evidenced counts as not met, not as passing. That
# is the honest reading -- an underwriter does not give credit for a control
# nobody can demonstrate -- and it means connecting a source genuinely raises
# the number rather than merely decorating it.

INSURANCE_CONTROLS = [
    {
        "id": "mfa",
        "name": "MFA on privileged accounts",
        "evidence_sources": ("identity", "cloud"),
        "failing_categories": ("Identity", "Cloud"),
    },
    {
        "id": "endpoint",
        "name": "Managed endpoints and patch cadence",
        "evidence_sources": ("endpoint",),
        "failing_categories": ("Network",),
    },
    {
        "id": "logging",
        "name": "Security logging and monitoring",
        "evidence_sources": ("siem",),
        "failing_categories": (),
    },
    {
        "id": "email",
        "name": "Email authentication (SPF, DKIM, DMARC)",
        "evidence_sources": (),          # visible from external discovery alone
        "failing_categories": ("Email",),
    },
    {
        "id": "inventory",
        "name": "Maintained asset inventory",
        "evidence_sources": ("cmdb",),
        "failing_categories": (),
    },
]


def compute_insurance_readiness(
    findings: List[Finding],
    assets: Optional[List[Asset]] = None,
    connected_sources: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Share of the controls underwriters ask for that could be evidenced.

    Returns the percentage plus a per-control breakdown, so the figure can be
    explained rather than merely quoted.
    """
    connected_sources = connected_sources or []
    assets = assets or []
    failing_categories = {f.category for f in findings}

    controls: List[Dict[str, Any]] = []
    for spec in INSURANCE_CONTROLS:
        needs = spec["evidence_sources"]
        # A control with no required source is evidenced by the external scan.
        evidenced = (not needs) or any(s in connected_sources for s in needs)

        # The inventory control also passes when discovery itself covered the
        # estate: every asset found is monitored.
        if spec["id"] == "inventory" and not evidenced:
            evidenced = bool(assets) and all(
                (a.status or "").lower() == "monitored" for a in assets
            )

        open_findings = [c for c in spec["failing_categories"] if c in failing_categories]

        if not evidenced:
            state, reason = "unverified", (
                f"No {' or '.join(needs)} source connected, so this cannot be evidenced"
            )
        elif open_findings:
            state, reason = "failing", f"Open {', '.join(open_findings)} finding(s)"
        else:
            state, reason = "met", "Evidenced with no open findings"

        controls.append({
            "id": spec["id"],
            "name": spec["name"],
            "state": state,
            "met": state == "met",
            "reason": reason,
        })

    met = sum(1 for c in controls if c["met"])
    total = len(controls)
    return {
        "readiness": round(100 * met / total) if total else 0,
        "controls_met": met,
        "controls_total": total,
        "controls": controls,
    }


# ---------------------------------------------------------------------------
# Causal risk graph
# ---------------------------------------------------------------------------
# The seven-layer graph -- threat, vulnerability, asset, identity, control gap,
# business service, financial loss -- built from the findings a scan produced
# rather than from a fixed fixture.
#
# The point of the view is attack-path collapse: thousands of raw findings
# reduce to a handful of chains that actually reach something worth money.
# Dominant paths are the findings carrying the most expected loss; everything
# else is drawn as noise so the collapse is visible.

# Which adversary archetype plausibly opens with a finding of this kind.
THREAT_BY_CATEGORY = {
    "Email": ("threat-phish", "Phishing Campaign"),
    "Identity": ("threat-cred", "Credential Stuffing"),
    "Network": ("threat-ransom", "Ransomware Group"),
    "Web App": ("threat-web", "Opportunistic Scanning"),
    "Cloud": ("threat-cloud", "Cloud Account Takeover"),
}

# Which control gap a finding in this category demonstrates.
CONTROL_GAP_BY_CATEGORY = {
    "Identity": ("gap-mfa", "No MFA"),
    "Cloud": ("gap-iam", "Over-permissive IAM"),
    "Network": ("gap-patch", "Unmanaged Patching"),
    "Web App": ("gap-patch", "Unmanaged Patching"),
    "Email": ("gap-email", "No Email Authentication"),
}

# Which business service sits behind an asset of this kind.
SERVICE_BY_CATEGORY = {
    "Identity": ("svc-admin", "Administrative Access"),
    "Cloud": ("svc-data", "Customer Data"),
    "Network": ("svc-ops", "Internal Operations"),
    "Web App": ("svc-portal", "Customer Portal"),
    "Email": ("svc-comms", "Business Communications"),
}

MAX_DOMINANT_PATHS = 4


def compute_causal_graph(
    findings: List[Finding],
    assets: Optional[List[Asset]] = None,
    connected_sources: Optional[List[str]] = None,
    eal_multiplier: float = 1.0,
) -> Dict[str, Any]:
    """
    Build the causal graph from real findings.

    Returns nodes, edges, and the headline counts the page displays. Dominant
    edges carry a `path` index (1-based); noise edges carry None.
    """
    assets = assets or []
    connected_sources = connected_sources or []
    asset_names = {a.id: a.asset_name for a in assets}

    if not findings:
        return {
            "nodes": [], "edges": [], "paths": [],
            "raw_findings": 0, "attack_paths": 0,
            "dominant_paths": 0, "total_eal": 0.0,
            "layers": ["Threat", "Vulnerability", "Asset", "Identity",
                       "Control Gap", "Business Service", "Financial Loss"],
        }

    # Business-critical assets come from the CMDB where one is connected.
    crown = {
        a.asset_name.lower()
        for a in assets
        if (a.tech_stack or {}).get("business_criticality") in {"Critical", "High"}
    }

    ranked = sorted(findings, key=lambda f: (f.eal or 0, f.final_risk_score or 0), reverse=True)
    dominant = ranked[:MAX_DOMINANT_PATHS]
    noise = ranked[MAX_DOMINANT_PATHS:]

    nodes: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, Any]] = []

    def node(node_id: str, layer: int, label: str, **meta) -> str:
        if node_id not in nodes:
            nodes[node_id] = {"id": node_id, "layer": layer, "label": label, **meta}
        return node_id

    def edge(src: str, dst: str, path: Optional[int]) -> None:
        # Never draw an edge twice at the same priority.
        for e in edges:
            if e["from"] == src and e["to"] == dst and e["path"] == path:
                return
        edges.append({"from": src, "to": dst, "path": path})

    total_eal = round(sum((f.eal or 0) for f in findings) * eal_multiplier, 1)
    loss_id = node("loss", 6, f"{total_eal:.1f}L Expected Loss", kind="loss", eal=total_eal)

    paths_meta: List[Dict[str, Any]] = []

    for index, f in enumerate(dominant, start=1):
        category = f.category or "Network"

        t_id, t_label = THREAT_BY_CATEGORY.get(category, ("threat-generic", "Opportunistic Attacker"))
        g_id, g_label = CONTROL_GAP_BY_CATEGORY.get(category, ("gap-generic", "Missing Control"))
        s_id, s_label = SERVICE_BY_CATEGORY.get(category, ("svc-ops", "Internal Operations"))

        asset_label = asset_names.get(f.asset_id, "External surface")
        # Key by name, not row id: findings arriving from different connectors
        # can point at the same host, and those must collapse to one node
        # rather than drawing the same asset four times.
        a_id = "asset-" + re.sub(r"[^a-z0-9]+", "-", asset_label.lower()).strip("-")
        v_id = f"vuln-{f.id}"

        # Identity layer: a privileged account is only implicated where the
        # finding actually concerns identity or cloud permissions.
        if category in ("Identity", "Cloud"):
            i_id, i_label = "id-priv", "Privileged Accounts"
        else:
            i_id, i_label = "id-user", "Standard Users"

        node(t_id, 0, t_label, kind="threat")
        node(v_id, 1, f.short or (f.issue or "Finding")[:18], kind="vulnerability",
             severity=f.severity, cve=f.cve_id, kev=bool(f.is_kev), eal=round((f.eal or 0) * eal_multiplier, 1))
        node(a_id, 2, asset_label, kind="asset",
             critical=asset_label.lower() in crown)
        node(i_id, 3, i_label, kind="identity")
        node(g_id, 4, g_label, kind="control_gap")
        node(s_id, 5, s_label, kind="service")

        for src, dst in ((t_id, v_id), (v_id, a_id), (a_id, i_id),
                         (i_id, g_id), (g_id, s_id), (s_id, loss_id)):
            edge(src, dst, index)

        paths_meta.append({
            "path": index,
            "label": f"{t_label} to {s_label}",
            "finding_id": f.id,
            "finding": f.issue or f.short,
            "eal": round((f.eal or 0) * eal_multiplier, 1),
            "severity": f.severity,
            "fix": f.short,
            "fix_cost": f.cost or 0,
            "breakpoint": g_id,
        })

    # Everything that did not make the cut, drawn as background noise so the
    # collapse from "all findings" to "a few paths that matter" is visible.
    if noise:
        noise_id = node("noise", 1, f"{len(noise)} lower-impact findings",
                        kind="vulnerability", aggregate=True, count=len(noise))
        seen_threats = {n["id"] for n in nodes.values() if n["layer"] == 0}
        for t_id in list(seen_threats)[:3]:
            edge(t_id, noise_id, None)
        for f in noise[:8]:
            label = asset_names.get(f.asset_id, "External surface")
            a_id = "asset-" + re.sub(r"[^a-z0-9]+", "-", label.lower()).strip("-")
            if a_id in nodes:
                edge(noise_id, a_id, None)

    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "paths": paths_meta,
        "raw_findings": len(findings),
        # A finding only opens a path if something downstream can be reached.
        "attack_paths": sum(1 for f in findings if (f.eal or 0) > 0),
        "dominant_paths": len(dominant),
        "total_eal": total_eal,
        "layers": ["Threat", "Vulnerability", "Asset", "Identity",
                   "Control Gap", "Business Service", "Financial Loss"],
    }
