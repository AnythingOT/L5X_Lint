# Third-party notices

L5X_Lint is licensed under the GNU GPL v3.0 only (see `LICENSE`). It uses the following work by
others. Every licence below is permissive, compatible with the GPL-3.0, and allows use, change and
redistribution with the notice kept.

## Python packages

Installed with `pip` from `requirements.txt`; none of them is copied into this repository. Their
licences come with them when installed.

| Package | Used for | Licence |
|---|---|---|
| Flask, Werkzeug, Jinja2, MarkupSafe, itsdangerous, click | the web UI | BSD-3-Clause |
| blinker (used by Flask) | | MIT |
| openpyxl, et-xmlfile | Excel report export | MIT |
| reportlab | PDF report export | BSD |
| pillow, charset-normalizer (used by reportlab) | | MIT-CMU, MIT |
| pypdf (tests only) | reading exported PDFs in `tests/test_rules.py` | BSD-3-Clause |

## Trademarks

Rockwell Automation, Studio 5000, Logix Designer, RSLogix 5000, ControlLogix, CompactLogix and
GuardLogix are trademarks of Rockwell Automation, Inc. They are used here only to say which files
this tool reads. L5X_Lint is not affiliated with or endorsed by Rockwell Automation.
