"""Every annotation in the package must evaluate eagerly. Python 3.14
defers annotation evaluation, so a missing typing import only surfaces on
3.12 and 3.13; this forces the evaluation on every version."""

import importlib
import inspect
import pathlib
import typing


def test_all_annotations_evaluate():
    problems = []
    for p in sorted((pathlib.Path(__file__).resolve().parent.parent / "gargoyle").glob("*.py")):
        if p.name == "__init__.py":
            continue
        m = importlib.import_module("gargoyle." + p.stem)
        for name, obj in list(vars(m).items()):
            if getattr(obj, "__module__", None) != m.__name__:
                continue
            targets = [obj] if inspect.isfunction(obj) else []
            if inspect.isclass(obj):
                targets = [obj] + [v for v in vars(obj).values() if inspect.isfunction(v)]
            for t in targets:
                try:
                    typing.get_type_hints(t)
                except Exception as exc:
                    problems.append((p.name, getattr(t, "__qualname__", name), repr(exc)))
    assert problems == []
