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

_PATHLIKE = re.compile(r"[\\/]|^[A-Za-z]:")
_DRIVE = re.compile(r"^([A-Za-z]:)(.*)$", re.S)


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


def comparable(glob: str, value: str):
    """Both sides as they are compared: normalized when either is a path."""
    if is_pathlike(value) or is_pathlike(glob):
        return normalize_path(glob), normalize_path(value)
    return glob, value


def glob_match(glob: str, value: str) -> bool:
    """Does the argument value match the glob? Paths normalized first."""
    g, v = comparable(glob, value)
    return fnmatch.fnmatchcase(v, g)
