"""Argument globs, as rules (gargoyle.rules) and plan steps (gargoyle.plans)
use them: `fnmatch` patterns over one argument value, with paths made safe
to match.

A raw `fnmatch` on a path is a hole: `C:\\proj\\*` is slipped by
`C:\\proj\\..\\secrets\\x`, by `c:\\PROJ\\x` on a case-insensitive disk and
by `C:/proj/x`. So when either side looks like a path (a separator, or a
drive letter), both are normalized first: separators become `/`, `.` and
`..` segments are resolved lexically, repeated separators collapse, and
the whole string is lower-cased, since the gate cannot know the target
filesystem's case rules and a rule meant for one folder must not be
slipped by a letter. Values that look like nothing of the kind (a mail
address, an account id) are matched exactly as written, case included.

`*` spans folders: a rule for `C:\\proj\\*` covers the whole tree under it.
There is no segment-bounded wildcard; a rule that wants one folder level
names it.
"""

import fnmatch
import posixpath
import re
from typing import Optional

_PATHLIKE = re.compile(r"[\\/]|^[A-Za-z]:")
_DRIVE = re.compile(r"^([A-Za-z]:)(.*)$", re.S)
_WINDOWS = re.compile(r"^[A-Za-z]:|^\\\\|\\")
_RESERVED_STEMS = frozenset({"con", "prn", "aux", "nul"} | {"com%d" % i for i in range(1, 10)} | {"lpt%d" % i for i in range(1, 10)})


def is_pathlike(value: str) -> bool:
    return bool(_PATHLIKE.search(value))


def normalize_path(value: str) -> str:
    """The comparable form of a path or path glob (see the module note)."""
    text = value.replace("\\", "/")
    drive = ""
    m = _DRIVE.match(text)
    if m:
        drive, text = m.group(1), m.group(2) or "/"
        if text.startswith("/"):
            text = "/" + text.lstrip("/")       # after a drive, repeated separators are just separators
    unc = not drive and text.startswith("//") and not text.startswith("///")
    text = posixpath.normpath(text) if text else ""
    if unc and not text.startswith("//"):
        text = "/" + text
    return (drive + text).lower()


def is_windows_path(value: str) -> bool:
    """A drive letter, a UNC prefix or a backslash: a name Windows will interpret."""
    return bool(_WINDOWS.search(value))


def canonical_path(value: str) -> str:
    """The name the filesystem will actually use. Windows strips trailing
    dots and spaces from every component and treats `name:stream` and
    `name::$DATA` as streams of `name`; a rule written `*.ps1` therefore
    has to cover `x.ps1.`, `x.ps1 ` and `x.ps1::$DATA`, all of which land
    on disk as `x.ps1` (soak test, 2026-11-01). Built on `normalize_path`;
    the drive prefix keeps its colon."""
    text = normalize_path(value)
    drive = ""
    m = _DRIVE.match(text)
    if m:
        drive, text = m.group(1), m.group(2)
    out = []
    for part in text.split("/"):
        if part in ("", ".", ".."):
            out.append(part)
            continue
        base = part.split(":", 1)[0].rstrip(". ")
        out.append(base if base else part)
    return drive + "/".join(out)


def path_rewrite_reason(value: str) -> Optional[str]:
    """Why Windows would not create the name as sent, or None when it would:
    a component the filesystem rewrites (trailing dot or space, a stream
    suffix) or a reserved device name. The gate refuses such a name before
    the rules see it, so the name the rules judged, the name the receipt
    binds and the name on disk are one name."""
    norm = normalize_path(value)
    canon = canonical_path(value)
    if canon != norm:
        return "the filesystem would rewrite it (trailing dot or space, or a stream suffix)"
    text = _DRIVE.match(canon).group(2) if _DRIVE.match(canon) else canon
    for part in text.split("/"):
        if part.split(".", 1)[0] in _RESERVED_STEMS:
            return "a reserved device name (%s)" % part
    return None


def comparable(glob: str, value: str):
    """Both sides as they are compared: normalized when either is a path."""
    if is_pathlike(value) or is_pathlike(glob):
        return normalize_path(glob), normalize_path(value)
    return glob, value


def glob_match(glob: str, value: str) -> bool:
    """Does the argument value match the glob? Paths normalized first, and a
    path is also tried in its canonical form, so a hold on `*.ps1` is not
    slipped by a name the filesystem will rewrite to one."""
    g, v = comparable(glob, value)
    if fnmatch.fnmatchcase(v, g):
        return True
    if is_pathlike(value) or is_pathlike(glob):
        c = canonical_path(value)
        return c != v and fnmatch.fnmatchcase(c, g)
    return False
