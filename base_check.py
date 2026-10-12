# checks/base_check.py
from dataclasses import dataclass

SEV_ORDER  = ["CRITICAL", "ERROR", "WARNING", "INFO", "DISABLED"]
VALID_SEVERITIES = set(SEV_ORDER)


@dataclass
class Finding:
    check_id:   str
    check_name: str
    severity:   str
    message:    str
    location:   str = ""
    detail:     str = ""
    # Checklist code (CRT001 …), stamped by rules.apply_registry.
    code:       str = ""

    def to_dict(self) -> dict:
        return {
            "check_id":   self.check_id,
            "check_name": self.check_name,
            "severity":   self.severity,
            "message":    self.message,
            "location":   self.location,
            "detail":     self.detail,
            "code":       self.code,
        }


def effective_severity(check_id: str, gate: dict) -> str:
    """
    Gate for a check: "DISABLED" when the rule is switched off (so the check
    skips its work), otherwise a placeholder severity. The real severity is
    fixed by the rule code and stamped later by rules.apply_registry.
    `gate` is built by rules.build_gate from the configured disabled rules.
    """
    return "DISABLED" if gate.get(check_id) == "DISABLED" else "WARNING"
