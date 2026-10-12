# severity.py — minimal replacement for the removed scorer module.
"""
The scoring system has been removed. A single 0-100 number invites
gameification (disabling rules to chase a score) without telling the
team anything that severity counts don't already say. The UI should
surface counts, not a fabricated grade.

What's kept from the old scorer module:
  severity_counts(findings) -> dict
"""

def severity_counts(findings) -> dict:
    counts = {"CRITICAL": 0, "ERROR": 0, "WARNING": 0, "INFO": 0}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1
    return counts
