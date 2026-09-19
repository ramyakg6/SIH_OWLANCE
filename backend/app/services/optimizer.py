"""Greedy Ratio Knapsack Investment Budget Optimizer Service"""
import logging
import time
from typing import List, Dict, Any, Set
from sqlalchemy.orm import Session
from app.db.models import Finding
from app.services.scoring import compute_org_score

logger = logging.getLogger(__name__)


def run_budget_optimizer(
    findings: List[Finding], budget: float
) -> Dict[str, Any]:
    """
    Greedy ratio knapsack budget optimizer.
    1. Unconditionally include all free fixes (cost == 0).
    2. Sort remaining non-free findings by efficiency ratio (reduction / cost) descending.
    3. Greedily allocate items that fit within the remaining budget.
    4. Compute projected_score by re-running compute_org_score() with selected findings zeroed out.
    5. Returns selected_findings, total_cost, remaining_budget, total_reduction, and projected_score.
    (Savings in ₹ is omitted for P0).
    """
    start_time = time.perf_counter()

    remaining_budget = float(budget)
    selected_findings: List[Finding] = []
    selected_ids: Set[int] = set()

    # Step 1: All free fixes (cost == 0) are always selected first
    free_fixes = [f for f in findings if f.cost == 0]
    for f in free_fixes:
        selected_findings.append(f)
        selected_ids.add(f.id)

    # Step 2: Sort remaining fixes by (reduction / cost) descending
    paid_fixes = [f for f in findings if f.cost > 0]
    paid_fixes.sort(key=lambda x: (x.reduction / x.cost), reverse=True)

    # Step 3: Greedily pick fixes that fit within budget
    for f in paid_fixes:
        if f.cost <= remaining_budget:
            selected_findings.append(f)
            selected_ids.add(f.id)
            remaining_budget -= f.cost

    total_cost = sum(f.cost for f in selected_findings)
    total_reduction = sum(f.reduction for f in selected_findings)

    # Step 4: Re-use compute_org_score() to determine the new projected score (300-900)
    projected_score = compute_org_score(findings, fixed_ids=selected_ids)

    duration_ms = (time.perf_counter() - start_time) * 1000.0
    logger.info(
        "Optimizer completed in %.2f ms (selected %d of %d findings)",
        duration_ms,
        len(selected_findings),
        len(findings),
    )

    return {
        "selected_findings": selected_findings,
        "total_cost": total_cost,
        "remaining_budget": remaining_budget,
        "total_reduction": total_reduction,
        "projected_score": projected_score,
        "execution_ms": duration_ms,
    }
