"""
Rule runners. Execution order is fixed — it determines finding order in reports.
The rule codes, titles and severities live in rules.py.
"""

from checks.common import Ctx, _all_rungs, _ucfg
from checks.io import ekey_disabled, io_alias, io_no_desc, io_unmapped
from checks.logic import _msg_stagger, array_bounds, div_zero, dup_instr, empty_branch, jmp_back, mov_real_int, oneshot_reuse, protected_writes, res_missing, timer_reuse
from checks.program import _ctrl_fault_handler, _prog_fault_routine, task_period_name
from checks.tags import _safety_std_map, desc_spare, pc_naming, small_int, timer_pre
from checks.udt import _udt_order, udt_member_desc, unused_type


ALL = [timer_pre, protected_writes, dup_instr, array_bounds, div_zero, jmp_back, timer_reuse, oneshot_reuse,
       res_missing, pc_naming, task_period_name, empty_branch, mov_real_int,
       small_int, io_unmapped, io_no_desc, ekey_disabled, desc_spare,
       unused_type, udt_member_desc, io_alias]


# Rule functions that emit a check_id different from their own name.
_EMITS = {"protected_writes": ("msg_write", "timer_wr")}


def _run_rule_set(data, cfg=None, gate=None):
    """Returns (findings, errors). A crashing rule is reported in `errors`
    (surfaced in the report banner) — never silently dropped."""
    ctx = Ctx(data)
    findings, errors = [], []
    from rules import is_enabled
    gate = gate or {}
    for fn in ALL:
        emits = _EMITS.get(fn.__name__, (fn.__name__,))
        if not any(is_enabled(cid, gate) for cid in emits):
            continue                              # rule switched off: skip the work
        try:
            findings += fn(ctx)
        except Exception as e:
            errors.append(f"{fn.__name__}: {e!r}")
    return findings, errors


def _run_verifiable_rules(data: dict, sev: dict, cfg: dict):
    u = _ucfg(cfg)
    F, und = [], {}
    rungs = list(_all_rungs(data))
    udts = {d["name"]: d for d in data.get("datatypes", [])}

    F += _safety_std_map(data, sev, u, und)
    F += _udt_order(data, sev)
    F += _msg_stagger(rungs, sev)
    F += _ctrl_fault_handler(data, sev, und)
    F += _prog_fault_routine(data, sev)
    return F, und



def run_rules(data: dict, cfg: dict, gate: dict):
    """
    Run the rule set, then the rules that can report "not verified".
    Returns (findings, rule_errors, not_verified{code: reason}).
    Order is fixed: it determines finding order in reports.
    """
    f1, errors = _run_rule_set(data, cfg, gate)
    f2, undetermined = _run_verifiable_rules(data, gate, cfg)
    return f1 + f2, errors, undetermined
