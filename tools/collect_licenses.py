"""Write the licence texts of everything a PyInstaller build bundles.

Run it with the same Python that runs PyInstaller, after `pip install -r requirements.txt`:

    python tools/collect_licenses.py -r requirements.txt -o dist/THIRD_PARTY_LICENSES.txt

It writes, into one plain-text file:
  1. the licence of the Python interpreter itself (LICENSE.txt of the running Python; on Windows
     that file also covers the libraries Python ships with, among them Tcl/Tk for tkinter);
  2. for every package named in the requirements file and every package those depend on, its
     name, version, licence and the full text of each licence file the package installed.

Standard library only, so it runs on Python 3.8 (the last Python for Windows 7) and needs no
extra install. Build tools (PyInstaller, pip, setuptools as a build tool) are not listed unless a
requirement depends on them: the PyInstaller bootloader is GPL-2.0 with an exception that lets
the built exe be shared under any licence.
"""
import argparse
import os
import re
import sys
import sysconfig

try:
    from importlib import metadata
except ImportError:  # pragma: no cover - Python < 3.8
    sys.exit("collect_licenses.py needs Python 3.8 or newer")

NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
# Weak-copyleft licences: sharing them in binary form also means telling people where the
# source is. (pattern searched in the licence label, case-insensitive)
SOURCE_OFFER = re.compile(r"MPL|Mozilla Public|LGPL|Lesser General|EPL|Eclipse Public", re.I)
SOURCE_NOTE = ("This licence asks that recipients can get the source of this package. It is "
               "available, unchanged, at the project URL above and at "
               "https://pypi.org/project/{name}/{version}/#files")


def norm(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def read_requirements(path):
    names = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if not line or line.startswith("-"):
                continue
            m = NAME_RE.match(line)
            if m:
                names.append(m.group(1))
    return names


def runtime_deps(dist):
    """Names this distribution requires, leaving out extras-only requirements."""
    out = []
    for req in dist.requires or []:
        if re.search(r"\bextra\s*==", req):
            continue
        m = NAME_RE.match(req)
        if m:
            out.append(m.group(1))
    return out


def walk(roots):
    """Installed distributions for roots and their dependencies, in a stable order."""
    seen, order, missing = set(), [], []
    stack = list(reversed(roots))
    while stack:
        name = stack.pop()
        key = norm(name)
        if key in seen:
            continue
        seen.add(key)
        try:
            dist = metadata.distribution(name)
        except metadata.PackageNotFoundError:
            # A dependency behind an environment marker that does not apply here is not installed,
            # so it is not bundled either. A missing *root* is a real problem.
            if name in roots:
                missing.append(name)
            continue
        order.append(dist)
        stack.extend(reversed(runtime_deps(dist)))
    return sorted(order, key=lambda d: norm(d.metadata["Name"])), missing


def licence_label(dist):
    md = dist.metadata
    expr = md.get("License-Expression")
    if expr:
        return expr
    classifiers = [c.split("::")[-1].strip() for c in md.get_all("Classifier") or []
                   if c.startswith("License ::")]
    if classifiers:
        return "; ".join(classifiers)
    text = (md.get("License") or "").strip()
    return text.splitlines()[0][:80] if text else "UNKNOWN"


def licence_files(dist):
    files = []
    for f in dist.files or []:
        base = os.path.basename(str(f)).lower()
        parent = str(f).replace("\\", "/").split("/")[0]
        # Only the package's own licence files (in its .dist-info), not ones vendored deeper down.
        if not parent.endswith(".dist-info"):
            continue
        if base.startswith(("licen", "copying", "notice", "authors")):
            files.append(f)
    return files


def project_url(dist):
    md = dist.metadata
    for entry in md.get_all("Project-URL") or []:
        label, _, url = entry.partition(",")
        if label.strip().lower() in ("source", "source code", "repository", "homepage", "home"):
            return url.strip()
    return (md.get("Home-page") or "").strip()


def warn(msg):
    # Shows up as an annotation in GitHub Actions; plain text elsewhere.
    prefix = "::warning::" if os.environ.get("GITHUB_ACTIONS") else "WARNING: "
    print(prefix + msg, file=sys.stderr)


def tcl_tk_licences():
    """Tcl/Tk licence.terms files that python.org Windows builds ship for tkinter."""
    found = []
    root = os.path.join(sys.base_prefix, "tcl")
    if os.path.isdir(root):
        for sub in sorted(os.listdir(root)):
            path = os.path.join(root, sub, "license.terms")
            if os.path.isfile(path) and re.match(r"(tcl|tk)\d", sub):
                with open(path, encoding="utf-8", errors="replace") as fh:
                    found.append((sub, fh.read()))
    return found


def python_licence():
    candidates = [
        os.path.join(sys.base_prefix, "LICENSE.txt"),            # Windows python.org install
        os.path.join(sysconfig.get_paths()["stdlib"], "LICENSE.txt"),
        os.path.join(sys.base_prefix, "LICENSE"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            with open(path, encoding="utf-8", errors="replace") as fh:
                return path, fh.read()
    return None, None


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-r", "--requirements", action="append", default=[],
                    help="requirements file (repeatable)")
    ap.add_argument("-p", "--package", action="append", default=[],
                    help="extra package to include (repeatable)")
    ap.add_argument("-o", "--output", required=True)
    ap.add_argument("--app", default="this program")
    ap.add_argument("--tkinter", action="store_true",
                    help="the program uses tkinter: also include the Tcl/Tk licences")
    args = ap.parse_args(argv)

    roots = list(args.package)
    for path in args.requirements:
        roots += read_requirements(path)
    dists, missing = walk(roots)
    if missing:
        sys.exit("not installed, so its licence cannot be collected: " + ", ".join(missing))

    bar = "=" * 78
    out = [
        "Third-party licences for {}".format(args.app),
        "",
        "This program is built with PyInstaller and contains the Python interpreter and the",
        "packages listed below. Their licences follow in full. The PyInstaller bootloader is",
        "GPL-2.0-or-later with an exception that allows the built program to be distributed",
        "under any licence.",
        "",
        "Contents:",
        "  Python {}.{}.{}".format(*sys.version_info[:3]),
    ]
    if args.tkinter:
        out.append("  Tcl/Tk (used by tkinter)")
    out += ["  {} {}  ({})".format(d.metadata["Name"], d.version, licence_label(d)) for d in dists]
    out.append("")

    path, text = python_licence()
    out += [bar, "Python {}.{}.{}".format(*sys.version_info[:3]),
            "https://www.python.org/  -  PSF License Agreement", bar, ""]
    if text:
        out += [text.rstrip(), ""]
    else:
        warn("Python's LICENSE.txt was not found under " + sys.base_prefix)
        out += ["Python's LICENSE.txt was not found next to this interpreter. The text is at",
                "https://docs.python.org/3/license.html", ""]

    if args.tkinter:
        tcl = tcl_tk_licences()
        if not tcl:
            warn("tkinter is bundled but no tcl/*/license.terms was found under " + sys.base_prefix)
        for sub, body in tcl:
            out += [bar, "{} (used by tkinter)".format(sub.capitalize()),
                    "https://www.tcl-lang.org/  -  Tcl/Tk licence (BSD-style)", bar, "",
                    body.rstrip(), ""]

    for d in dists:
        name, label = d.metadata["Name"], licence_label(d)
        out += [bar, "{} {}".format(name, d.version), project_url(d), "Licence: " + label, bar, ""]
        if SOURCE_OFFER.search(label):
            out += [SOURCE_NOTE.format(name=name, version=d.version), ""]
        files = licence_files(d)
        if not files:
            warn("{} {} installed no licence file; add its text by hand".format(name, d.version))
            out += ["(This package installed no licence file. Licence declared in its metadata: "
                    + label + ")", ""]
        for f in files:
            with open(str(f.locate()), encoding="utf-8", errors="replace") as fh:
                body = fh.read().rstrip()
            out += ["--- " + os.path.basename(str(f)) + " ---", body, ""]

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(out) + "\n")
    print("wrote {} (Python + {} packages)".format(args.output, len(dists)))


if __name__ == "__main__":
    main()
