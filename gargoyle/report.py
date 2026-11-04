"""`gargoyle report`: the quarterly evidence report, produced from the record.

The verification already lives in `gargoyle audit`, `doctor`, `sidedoors` and
the issuer's endpoints. What a quarterly review adds is the joining and the
counting: who asked, for what, who answered, how fast, by day and by account,
and the raw outputs kept with their hashes so a third party can repeat it.
Until this module that was done by hand (the two reviews of 2026-11-02).

    period_summary(entries, since, until) -> the tables, as data
    render_markdown(summary, checks, ...) -> REPORT.md
    run_report(args)                     -> snapshot, checks, REPORT.md, SHA256SUMS

The report states what the record says. The verdict, the findings and the
charter status are judgment, so they come from a hand-written preface
(`--preface FILE`) that is placed above the tables, never generated.
"""

import collections
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

NOT_RECORDED = "not recorded"
MCP_FS = "mcp://filesystem/"


def _at(e: Dict[str, Any]) -> Optional[datetime]:
    try:
        t = datetime.fromisoformat(str(e.get("at")))
    except (TypeError, ValueError):
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def _in(e: Dict[str, Any], since: Optional[datetime], until: Optional[datetime]) -> bool:
    t = _at(e)
    if t is None:
        return False
    return (since is None or t >= since) and (until is None or t <= until)


def _target(url: Any) -> str:
    s = str(url or "")
    return s[len(MCP_FS):] if s.startswith(MCP_FS) else (s or NOT_RECORDED)


def _stats(xs: List[float]) -> Optional[Dict[str, float]]:
    if not xs:
        return None
    xs = sorted(xs)
    return {"min": xs[0], "median": xs[len(xs) // 2], "max": xs[-1], "count": len(xs)}


def period_summary(entries: List[Any], since: Optional[datetime] = None, until: Optional[datetime] = None) -> Dict[str, Any]:
    """Every table of the report, as data, from witness entries. Answers are
    joined to their holds by approval_request_id; an answer written since
    the request-summary release (#25) carries who asked and what for on its
    own, and that is preferred. Pure: no I/O."""
    all_rows = [e for e in entries if isinstance(e, dict)]
    rows = [e for e in all_rows if _in(e, since, until)]
    head = all_rows[-1] if all_rows else {}
    issued = [e for e in rows if e.get("event") == "issued"]
    plans = [e for e in rows if e.get("event") == "plan"]
    granted = [e for e in rows if e.get("event") == "granted"]
    declined = [e for e in rows if e.get("event") == "declined"]
    refused = [e for e in rows if e.get("event") == "refused"]
    grant_refused = [e for e in rows if e.get("event") == "grant_refused"]
    started = [e for e in rows if e.get("event") == "started"]
    by_arid: Dict[str, Dict[str, Any]] = {}
    for e in all_rows:                                   # joins may reach before the period: a hold answered later
        if e.get("event") == "issued" and isinstance(e.get("approval_request_id"), str):
            by_arid[e["approval_request_id"]] = e
    plan_arids = {e.get("approval_request_id") for e in all_rows if e.get("event") == "plan"}

    def answer_row(e: Dict[str, Any]) -> Dict[str, Any]:
        arid = e.get("approval_request_id")
        hold = by_arid.get(arid) if isinstance(arid, str) else None
        asked = e.get("requested_by") or (hold or {}).get("principal") or ""
        # An answer whose hold is not an issued receipt answers a plan: the issuer
        # holds nothing else. Older plan answers carry neither plan id nor asker.
        tool = e.get("tool") or (hold or {}).get("tool") or ("plan" if (e.get("plan_id") or e.get("hold_kind") == "plan" or arid in plan_arids or hold is None) else "")
        held_at = _at(hold) if hold else None
        t = _at(e)
        return {"at": e.get("at", ""), "seq": e.get("seq", 0), "event": e.get("event"), "asked_by": asked, "tool": tool or NOT_RECORDED,  # asked_by "" = not joinable
                "target": _target(e.get("target_url") or (hold or {}).get("target_url")),
                "what": e.get("summary") or NOT_RECORDED, "request": e.get("request") if isinstance(e.get("request"), dict) else None,
                "by": e.get("by") or e.get("approver") or "", "why": e.get("why") or "", "reason": e.get("reason") or "",
                "roles": list(e.get("roles") or []), "plan_id": e.get("plan_id") or (hold or {}).get("plan_id") or "",
                "approval_request_id": arid or "",
                "seconds": (t - held_at).total_seconds() if (t and held_at) else None}

    # Newest first. Two entries written in the same clock tick share a timestamp
    # (seen on Windows), so the witness sequence breaks the tie.
    newest = lambda r: (r["at"], r.get("seq") or 0)
    decline_rows = sorted((answer_row(e) for e in declined), key=newest, reverse=True)
    release_rows = sorted((answer_row(e) for e in granted), key=newest, reverse=True)
    grant_refused_rows = sorted((answer_row(e) for e in grant_refused), key=newest, reverse=True)
    refusal_rows = sorted(({"at": e.get("at", ""), "seq": e.get("seq", 0), "asked_by": e.get("principal") or "", "tool": e.get("tool") or "",
                            "target": _target(e.get("target_url")), "what": e.get("summary") or NOT_RECORDED,
                            "request": e.get("request") if isinstance(e.get("request"), dict) else None,
                            "reason": e.get("reason") or "", "why": e.get("why") or "", "declines": e.get("declines")}
                           for e in refused), key=newest, reverse=True)

    accounts: Dict[str, Dict[str, Any]] = {}

    def acct(p: str) -> Dict[str, Any]:
        return accounts.setdefault(p, {"receipts": 0, "held": 0, "plans_held": 0, "released": 0, "declined": 0, "refused": 0,
                                       "tools": collections.Counter(), "answered_by": collections.Counter()})
    for e in issued:
        a = acct(str(e.get("principal") or ""))
        a["receipts"] += 1
        a["tools"][str(e.get("tool") or "")] += 1
        if e.get("held"):
            a["held"] += 1
    for e in plans:
        if e.get("held"):
            acct(str(e.get("principal") or ""))["plans_held"] += 1
    unjoined = 0
    for r in release_rows:
        if not r["asked_by"]:
            unjoined += 1; continue
        a = acct(r["asked_by"]); a["released"] += 1; a["answered_by"][r["by"]] += 1
    for r in decline_rows:
        if not r["asked_by"]:
            unjoined += 1; continue
        a = acct(r["asked_by"]); a["declined"] += 1; a["answered_by"][r["by"]] += 1
    for r in refusal_rows:
        if r["asked_by"]:
            acct(r["asked_by"])["refused"] += 1

    by_day: Dict[str, Dict[str, Any]] = {}
    for e in rows:
        d = str(e.get("at", ""))[:10]
        if not d:
            continue
        day = by_day.setdefault(d, {"receipts": collections.Counter(), "released": 0, "declined": 0, "refused": 0})
        if e.get("event") == "issued":
            day["receipts"][str(e.get("principal") or "")] += 1
        elif e.get("event") == "granted":
            day["released"] += 1
        elif e.get("event") == "declined":
            day["declined"] += 1
        elif e.get("event") == "refused":
            day["refused"] += 1

    key_events = collections.Counter(e.get("event") for e in rows if e.get("event") in ("enrolled", "enroll_refused", "revoked"))
    key_rows = sorted(({"at": e.get("at", ""), "seq": e.get("seq", 0), "event": e.get("event"), "who": e.get("by") or e.get("approver") or e.get("principal") or "",
                        "reason": e.get("reason") or "", "replaced": bool(e.get("replaced"))}
                       for e in rows if e.get("event") in ("enrolled", "enroll_refused", "revoked")), key=lambda r: (r["at"], r["seq"] or 0), reverse=True)
    sidedoor_rows = [{"at": e.get("at", ""), "target": _target(e.get("target_url")), "count": e.get("count"), "kinds": e.get("kinds") or {}}
                     for e in rows if e.get("event") == "sidedoors"]
    with_summary = sum(1 for r in decline_rows + release_rows if r["what"] != NOT_RECORDED)
    return {
        "first_at": rows[0].get("at") if rows else None, "last_at": rows[-1].get("at") if rows else None,
        "head": {"seq": head.get("seq"), "entry_sha256": head.get("entry_sha256"), "at": head.get("at")},
        "since": since.isoformat() if since else None, "until": until.isoformat() if until else None,
        "entries": len(rows), "issued": len(issued), "held": sum(1 for e in issued if e.get("held")),
        "covered": sum(1 for e in issued if e.get("covered")),
        "plans": {"held": sum(1 for e in plans if e.get("held")), "allowed": sum(1 for e in plans if not e.get("held"))},
        "released": len(granted), "declined": len(declined), "refused": len(refused), "grant_refused": len(grant_refused),
        "restarts": sum(1 for e in started if e.get("resumed")), "began": sum(1 for e in started if not e.get("resumed")),
        "accounts": {p: {**a, "tools": dict(a["tools"]), "answered_by": dict(a["answered_by"])} for p, a in accounts.items()},
        "by_day": {d: {**x, "receipts": dict(x["receipts"])} for d, x in sorted(by_day.items(), reverse=True)},
        "declines": decline_rows, "releases": release_rows, "refusals": refusal_rows, "grant_refusals": grant_refused_rows,
        "answer_seconds": _stats([r["seconds"] for r in decline_rows + release_rows if r["seconds"] is not None]),
        "release_seconds": _stats([r["seconds"] for r in release_rows if r["seconds"] is not None]),
        "with_summary": with_summary, "without_summary": len(decline_rows) + len(release_rows) - with_summary,
        "key_events": dict(key_events), "key_rows": key_rows, "sidedoors": sidedoor_rows,
        "declines_without_reason": sum(1 for r in decline_rows if not r["why"]),
        "unjoined_answers": unjoined,
    }


# ---- output-line parsers for the commands the report runs -------------------------------------

_ENTRIES = re.compile(r"(\d+) entries \((\d+) honored, (\d+) refused\), (\d+) failed; chain ([A-Za-z_]+)")
_RECON = re.compile(r"reconciled: (\d+) issued by the issuer, (\d+) in evidence, (\d+) finding")
_WITNESS = re.compile(r"witness: (\d+) entries, (\S+), tail (\S+)")
_TREE = re.compile(r"tree: (\d+) gated file\(s\) checked, (\d+) untouched by the gate, (\d+) changed outside it")


def parse_audit_output(text: str) -> Dict[str, Any]:
    """The numbers out of `gargoyle audit --summary [--witness]` output."""
    out: Dict[str, Any] = {}
    m = _ENTRIES.search(text)
    if m:
        out.update(entries=int(m[1]), honored=int(m[2]), refused=int(m[3]), failed=int(m[4]), chain=m[5])
    m = _RECON.search(text)
    if m:
        out.update(issued=int(m[1]), in_evidence=int(m[2]), findings=int(m[3]))
    m = _WITNESS.search(text)
    if m:
        out.update(witness_entries=int(m[1]), witness_reason=m[2], witness_tail=m[3])
    m = _TREE.search(text)
    if m:
        out.update(tree_checked=int(m[1]), tree_untouched=int(m[2]), tree_changed=int(m[3]))
    out["finding_lines"] = [ln.strip() for ln in text.splitlines() if ln.strip().startswith("FINDING ")]
    return out


def parse_doctor_output(text: str) -> Dict[str, int]:
    c = collections.Counter()
    for ln in text.splitlines():
        head = ln.split(" ", 1)[0]
        if head in ("PASS", "WARN", "FAIL", "SKIP"):
            c[head] += 1
    return {k: c.get(k, 0) for k in ("PASS", "WARN", "FAIL", "SKIP")}


# ---- rendering ---------------------------------------------------------------------------------

def _cell(s: Any) -> str:
    return str(s if s is not None else "").replace("|", "\\|").replace("\n", " ")


def _table(header: List[str], rows: List[List[Any]]) -> str:
    lines = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    lines += ["| " + " | ".join(_cell(c) for c in r) + " |" for r in rows]
    return "\n".join(lines)


def _when(iso: Any) -> str:
    """"2 Nov 19:39" in UTC. No `%-d`: Windows strftime has no such flag."""
    t = _at({"at": iso})
    if not t:
        return str(iso or "")
    t = t.astimezone(timezone.utc)
    return "%d %s" % (t.day, t.strftime("%b %H:%M"))


def _day(d: str) -> str:
    """"2 November 2026" from "2026-11-02"."""
    t = datetime.fromisoformat(d)
    return "%d %s" % (t.day, t.strftime("%B %Y"))


def _plural(n: int, w: str) -> str:
    return "%d %s%s" % (n, w, "" if n == 1 else "s")


def render_markdown(summary: Dict[str, Any], checks: List[Dict[str, Any]], *, title: str, prepared_by: str,
                    generated_at: str, preface: str = "", commands: Optional[List[str]] = None,
                    extras: Optional[Dict[str, Any]] = None, hashes: Optional[List[List[str]]] = None) -> str:
    s = summary
    x = extras or {}
    head = s["head"]
    out: List[str] = []
    out.append("# %s" % title)
    out.append("")
    out.append("Evidence review · %s · Prepared by %s" % (generated_at[:10], prepared_by))
    out.append("")
    if preface.strip():
        out.append(preface.strip())
        out.append("")
    else:
        out.append("No preface was supplied. The sections below are the record as the commands read it; the verdict, "
                   "the findings and the charter status are written by the reviewer and placed here with `--preface`.")
        out.append("")
    period = "%s to %s UTC" % ((s["first_at"] or "")[:16].replace("T", " "), (s["last_at"] or "")[:16].replace("T", " "))
    out.append("## Record summary")
    out.append("")
    out.append("Period covered: %s. Witness snapshot head: sequence %s, tail `%s`. In the period the gate issued %s, "
               "held %s and %s for a person, released %d, declined %d, and refused %d on its own. %s. "
               "%d of the %d answers carry what was asked; %d predate the request-summary release and show the tool only."
               % (period, head.get("seq"), str(head.get("entry_sha256") or "")[:8], _plural(s["issued"], "receipt"),
                  _plural(s["held"], "action"), _plural(s["plans"]["held"], "plan"), s["released"], s["declined"], s["refused"],
                  ("The issuer was restarted %d time%s; every restart resumed the chain" % (s["restarts"], "" if s["restarts"] == 1 else "s")) if s["restarts"] else "The issuer was not restarted",
                  s["with_summary"], s["with_summary"] + s["without_summary"], s["without_summary"]))
    out.append("")
    out.append("## Verification results")
    out.append("")
    out.append("Exit 0 means every entry verified; exit 1 names the entry or the finding. Each raw output is in `raw/` with its hash in the appendix.")
    out.append("")
    out.append(_table(["Check", "What it proves", "Result"], [[c["check"], c["proves"], c["result"]] for c in checks]))
    out.append("")
    out.append("## Activity in the period")
    out.append("")
    out.append("Every receipt names the account that asked; every hold names the account that answered and, since the request-summary "
               "release, what was asked. Refused means refused by the service without a card.")
    out.append("")
    acc_rows = []
    for p, a in sorted(s["accounts"].items(), key=lambda kv: -kv[1]["receipts"]):
        answered = ", ".join("%s (%d)" % (k or "unknown", n) for k, n in sorted(a["answered_by"].items(), key=lambda kv: -kv[1])) or ("nobody; allowed by rule" if a["receipts"] else "")
        held = ("%d actions" % a["held"] + (", %d plans" % a["plans_held"] if a["plans_held"] else "")) if (a["held"] or a["plans_held"]) else "0, all allowed by rule"
        acc_rows.append([p or "unknown", a["receipts"], held, a["released"] or "", a["declined"] or "", a["refused"] or "", answered])
    out.append(_table(["Who asked", "Receipts", "Held", "Released", "Declined", "Refused", "Who answered"], acc_rows))
    out.append("")
    if s["unjoined_answers"]:
        n = s["unjoined_answers"]
        out.append("%s to plans held before the request-summary release; the witness did not then record who submitted the plan, so %s not counted against an account above and %s \"%s\" as the asker below."
                   % (("1 answer is" if n == 1 else "%d answers are" % n), "it is" if n == 1 else "they are", "shows" if n == 1 else "show", NOT_RECORDED))
        out.append("")
    principals = [p for p, _ in sorted(s["accounts"].items(), key=lambda kv: -kv[1]["receipts"])]
    day_rows = [[_day(d)] + [x_["receipts"].get(p, 0) for p in principals] + [x_["released"], x_["declined"], x_["refused"]]
                for d, x_ in s["by_day"].items()]
    out.append(_table(["Day (UTC)"] + ["Receipts: %s" % p for p in principals] + ["Released", "Declined", "Refused"], day_rows))
    out.append("")
    tool_bits = []
    for p in principals:
        tools = s["accounts"][p]["tools"]
        tool_bits.append("%s: %s" % (p, ", ".join("%d `%s`" % (n, t) for t, n in sorted(tools.items(), key=lambda kv: -kv[1]))))
    out.append("Calls by tool. " + ". ".join(tool_bits) + ".")
    if s["answer_seconds"]:
        a = s["answer_seconds"]
        out.append("Time from hold to answer, where the hold is in the record: %d to %d seconds, median %d, over %d answers." % (a["min"], a["max"], a["median"], a["count"]))
    out.append("")
    out.append("Declines, newest first. \"What was asked\" is the sentence the approver saw on the card, kept in the witness since the "
               "request-summary release; \"%s\" marks an answer older than that. %s carried no reason."
               % (NOT_RECORDED, _plural(s["declines_without_reason"], "decline").capitalize()))
    out.append("")
    out.append(_table(["When (UTC)", "Asked by", "For", "Target", "What was asked", "Declined by", "Reason"],
                      [[_when(r["at"]), r["asked_by"] or NOT_RECORDED, r["tool"], r["target"], r["what"], r["by"], r["why"] or "(no reason)"] for r in s["declines"]]))
    out.append("")
    out.append("Releases, newest first.")
    out.append("")
    out.append(_table(["When (UTC)", "Asked by", "For", "Target", "What was asked", "Released by", "Role"],
                      [[_when(r["at"]), r["asked_by"] or NOT_RECORDED, r["tool"], r["target"], r["what"], r["by"], "/".join(r["roles"]) or "before roles"] for r in s["releases"]]))
    out.append("")
    if s["refusals"]:
        out.append("Refused by the service without a card, newest first. A repeat of a request declined twice that day is refused with the last reason quoted back; a destructive tool, or a script where the rules prohibit one, is refused by rule. \"What was asked\" is recorded since the refusal-summary release; older rows show \"%s\"." % NOT_RECORDED)
        out.append("")
        out.append(_table(["When (UTC)", "Asked by", "For", "Target", "What was asked", "Reason", "Last decline quoted"],
                          [[_when(r["at"]), r["asked_by"], r["tool"], r["target"], r["what"], r["reason"], r["why"]] for r in s["refusals"]]))
        out.append("")
    if s["grant_refusals"]:
        out.append("Releases refused by the service (a grant under a key it does not trust), newest first.")
        out.append("")
        out.append(_table(["When (UTC)", "Asked by", "For", "What was asked", "Signed by", "Reason"],
                          [[_when(r["at"]), r["asked_by"], r["tool"], r["what"], r["by"], r["reason"]] for r in s["grant_refusals"]]))
        out.append("")
    out.append("## Approver keys")
    out.append("")
    ke = s["key_events"]
    out.append("In the period: %s, %s refused, %s." % (_plural(ke.get("enrolled", 0), "enrollment"), ke.get("enroll_refused", 0), _plural(ke.get("revoked", 0), "revocation")))
    if x.get("approvers"):
        out.append("Approvers known to the issuer with every key they have held: " + "; ".join("%s (%d key%s)" % (p, len(k), "" if len(k) == 1 else "s") for p, k in x["approvers"].items()) + ".")
    out.append("")
    if s["key_rows"]:
        out.append(_table(["When (UTC)", "Event", "Who", "Detail"],
                          [[_when(r["at"]), r["event"], r["who"], ("key replaced" if r["replaced"] else r["reason"])] for r in s["key_rows"]]))
        out.append("")
    out.append("## Routes around the gate")
    out.append("")
    if x.get("sidedoors") is not None:
        sd = x["sidedoors"]
        kinds = collections.Counter(f.get("kind") for f in sd.get("findings", []))
        out.append("Discovery run for this report on %s: %s%s." % (x.get("sidedoors_host", "this host"), _plural(len(sd.get("findings", [])), "finding"),
                   (" (" + ", ".join("%d %s" % (n, k) for k, n in sorted(kinds.items())) + ")") if kinds else ""))
        out.append("")
        if sd.get("findings"):
            out.append(_table(["Kind", "Path"], [[f.get("kind"), f.get("path")] for f in sd["findings"]]))
            out.append("")
    if s["sidedoors"]:
        out.append("Discovery reports recorded in the witness in the period:")
        out.append("")
        out.append(_table(["When (UTC)", "Target", "Findings", "Kinds"],
                          [[_when(r["at"]), r["target"], r["count"], ", ".join("%d %s" % (n, k) for k, n in sorted(r["kinds"].items()))] for r in s["sidedoors"]]))
        out.append("")
    if x.get("sidedoors") is None and not s["sidedoors"]:
        out.append("No discovery report was run for this report (pass `--env`) and none is recorded in the witness for the period.")
        out.append("")
    out.append("## How to repeat this review")
    out.append("")
    out.append("Anyone with the evidence logs, the witness snapshot and the public keys can repeat every check above without the issuer being "
               "reachable; with the issuer reachable, the approver key history is fetched live. The verifier is Apache 2.0 licensed and "
               "installs with `pip install gargoyle-receipts`.")
    out.append("")
    out.append("```")
    out.extend(commands or ["gargoyle report --witness witness.jsonl --out report/"])
    out.append("```")
    out.append("")
    out.append("Attestation. This report was produced on %s by %s with `gargoyle report`, against a copy of the witness taken at the start of the run. "
               "Witness head at snapshot: sequence %s, tail `%s`.%s%s The raw output of every command is kept in `raw/` and hashed in `SHA256SUMS`."
               % (generated_at, prepared_by, head.get("seq"), str(head.get("entry_sha256") or "")[:8],
                  (" Rules pin: `%s`." % x["rules_pin"][:8]) if x.get("rules_pin") else "",
                  (" Issuer key: `%s`." % x["issuer_key_id"]) if x.get("issuer_key_id") else ""))
    out.append("")
    out.append("## Appendix: raw outputs and their hashes")
    out.append("")
    for h, f in (hashes or []):
        out.append("- `%s…` `%s`" % (h[:16], f))
    out.append("")
    out.append("Full hashes: `SHA256SUMS` beside this file.")
    out.append("")
    return "\n".join(out)


# ---- the command --------------------------------------------------------------------------------

def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _run(cmd: List[str], out_file: Path) -> int:
    """Run a command, keep stdout and stderr together in out_file, return its exit code."""
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=dict(os.environ))
    out_file.write_text(p.stdout, encoding="utf-8")
    return p.returncode


def _date(s: Optional[str], end: bool = False) -> Optional[datetime]:
    if not s:
        return None
    t = datetime.fromisoformat(s)
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    if end and len(s) == 10:
        t = t.replace(hour=23, minute=59, second=59)
    return t


def run_report(args: Any) -> int:
    """The command. Returns 0 when every check accepted, 1 when any failed,
    2 on usage. The report is written in either of the first two cases."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from gargoyle.witness import read_witness, verify_witness
    witness = Path(args.witness)
    if not witness.exists():
        print("witness file not found: %s" % witness, file=sys.stderr)
        return 2
    out = Path(args.out).resolve()
    raw = out / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    started = datetime.now(timezone.utc)
    stamp = started.strftime("%Y-%m-%dT%H:%M:%SZ")
    (raw / "run-started.txt").write_text(stamp + "\n", encoding="utf-8")
    snapshot = raw / "witness-snapshot.jsonl"
    shutil.copyfile(witness, snapshot)
    entries = read_witness(str(snapshot))
    checks: List[Dict[str, Any]] = []
    commands: List[str] = ["%s %s raw/witness-snapshot.jsonl" % ("copy" if os.name == "nt" else "cp", witness)]
    extras: Dict[str, Any] = {}
    gargoyle_cmd = [sys.executable, "-m", "gargoyle"]

    # Keys: --keys, else beside the first log, else the output folder (the places `audit` looks).
    keys_dir: Optional[Path] = None
    for cand in ([Path(args.keys)] if getattr(args, "keys", None) else []) + [Path(l).resolve().parent for l in (args.log or [])] + [out]:
        if (cand / "public-keys.json").exists():
            keys_dir = cand
            break
    issuer_keys: Dict[str, Any] = {}
    if keys_dir is not None:
        try:
            keys = json.loads((keys_dir / "public-keys.json").read_text(encoding="utf-8"))
            issuer_keys = {k: Ed25519PublicKey.from_public_bytes(bytes.fromhex(v)) for k, v in dict(keys.get("issuer", {})).items()}
        except (OSError, ValueError, KeyError) as exc:
            print("public-keys.json unreadable in %s: %s" % (keys_dir, exc), file=sys.stderr)
    if issuer_keys:
        w = verify_witness(entries, issuer_public_keys=issuer_keys)
        checks.append({"check": "Issuer witness, chain and signatures", "proves": "No entry was inserted, removed or altered since the issuer wrote it",
                       "result": "%d entries, `%s`, tail `%s`" % (w["count"], w["reason"], w["tail_sha256"][:8]), "accepted": bool(w["accepted"])})
        extras["issuer_key_id"] = next(iter(issuer_keys))
    else:
        checks.append({"check": "Issuer witness, chain and signatures", "proves": "No entry was inserted, removed or altered since the issuer wrote it",
                       "result": "not verified: no public-keys.json found (pass --keys DIR)", "accepted": None})

    for log in (args.log or []):
        name = Path(log).stem
        cmd = gargoyle_cmd + ["audit", "--log", log, "--witness", str(snapshot), "--summary"] + (["--issuer", args.issuer] if args.issuer else []) + (["--out", str(keys_dir)] if keys_dir else [])
        rc = _run(cmd, raw / ("audit-%s.txt" % name))
        commands.append("gargoyle " + " ".join(cmd[3:]).replace(str(snapshot), "raw/witness-snapshot.jsonl"))
        p = parse_audit_output((raw / ("audit-%s.txt" % name)).read_text(encoding="utf-8"))
        if "entries" in p:
            res = "%d entries (%d honored, %d refused), %d failed, `%s`" % (p["entries"], p["honored"], p["refused"], p["failed"], p["chain"])
            if "findings" in p:
                res += "; reconciliation: %s" % _plural(p["findings"], "finding")
            res += "; exit %d" % rc
            if p["finding_lines"]:
                res += ". " + " ".join(p["finding_lines"][:6])
        else:
            res = "audit did not run to completion (exit %d); see `raw/audit-%s.txt`" % (rc, name)
        checks.append({"check": "Evidence log `%s` against the witness%s" % (Path(log).name, " and the issuer" if args.issuer else ""),
                       "proves": "Every receipt the client acted on was signed by the issuer; every human release by a key the issuer had enrolled; every row reconciles with the witness",
                       "result": res, "accepted": rc == 0})
        if args.check_tree:
            cmd = gargoyle_cmd + ["audit", "--log", log, "--check-tree", args.check_tree] + (["--out", str(keys_dir)] if keys_dir else [])
            rc = _run(cmd, raw / ("tree-%s.txt" % name))
            commands.append("gargoyle " + " ".join(cmd[3:]))
            p = parse_audit_output((raw / ("tree-%s.txt" % name)).read_text(encoding="utf-8"))
            res = ("%d gated file(s) checked, %d untouched by the gate, %d changed outside it; exit %d" % (p["tree_checked"], p["tree_untouched"], p["tree_changed"], rc)) if "tree_checked" in p else "tree check did not run (exit %d)" % rc
            if p.get("finding_lines"):
                res += ". " + " ".join(p["finding_lines"][:6])
            checks.append({"check": "Tree check, `%s` under `%s`" % (Path(log).name, args.check_tree), "proves": "Every file the gate wrote is as the gate left it",
                           "result": res, "accepted": rc == 0})

    if args.env:
        rc = _run(gargoyle_cmd + ["doctor", "--env", args.env], raw / "doctor.txt")
        commands.append("gargoyle doctor --env %s" % args.env)
        d = parse_doctor_output((raw / "doctor.txt").read_text(encoding="utf-8"))
        checks.append({"check": "Client health, `gargoyle doctor`", "proves": "The client, its trust in the issuer, its clock and its hook are as installed",
                       "result": "%d pass, %d fail, %d warn, %d skip; exit %d" % (d["PASS"], d["FAIL"], d["WARN"], d["SKIP"], rc), "accepted": rc == 0})
        rc = _run(gargoyle_cmd + ["sidedoors", "--env", args.env, "--json"] + (["--report"] if getattr(args, "report_sidedoors", False) else []), raw / "sidedoors.json")
        commands.append("gargoyle sidedoors --env %s --json%s" % (args.env, " --report" if getattr(args, "report_sidedoors", False) else ""))
        try:
            extras["sidedoors"] = json.loads((raw / "sidedoors.json").read_text(encoding="utf-8"))
            extras["sidedoors_host"] = os.uname().nodename if hasattr(os, "uname") else "this host"
            checks.append({"check": "Routes around the gate, `gargoyle sidedoors`", "proves": "What the rules cannot reach is named, not assumed",
                           "result": _plural(len(extras["sidedoors"].get("findings", [])), "finding") + " (listed below)", "accepted": None})
        except ValueError:
            checks.append({"check": "Routes around the gate, `gargoyle sidedoors`", "proves": "What the rules cannot reach is named, not assumed",
                           "result": "discovery did not produce a report (exit %d); see `raw/sidedoors.json`" % rc, "accepted": False})

    if args.issuer:
        import requests
        base = args.issuer.rstrip("/")
        for path, fname in (("/health", "health.json"), ("/keys", "keys.json"), ("/approvers/audit", "approvers-audit.json")):
            try:
                r = requests.get(base + path, timeout=15)
                (raw / fname).write_text(r.text, encoding="utf-8")
                commands.append("curl %s%s > raw/%s" % (base, path, fname))
                if path == "/health" and r.ok:
                    h = r.json()
                    extras["rules_pin"] = (h.get("policy") or {}).get("policy_sha256", "")
                    wh = h.get("witness_head") or {}
                    checks.append({"check": "Issuer health, `/health`", "proves": "The service is up, persistent, on the pinned rules",
                                   "result": "ok=%s, rules `%s`, persistent=%s, %s pending, witness head %s" % (h.get("ok"), extras["rules_pin"][:8], h.get("persistent"), h.get("pending_receipts"), wh.get("seq")),
                                   "accepted": bool(h.get("ok"))})
                if path == "/approvers/audit" and r.ok:
                    extras["approvers"] = dict(r.json().get("approvers", {}))
            except Exception as exc:        # the report says the issuer was unreachable; it does not stop
                (raw / fname).write_text("unreachable: %s\n" % exc, encoding="utf-8")
                if path == "/health":
                    checks.append({"check": "Issuer health, `/health`", "proves": "The service is up", "result": "unreachable: %s" % str(exc)[:120], "accepted": False})
    if getattr(args, "rules", None) and Path(args.rules).exists():
        shutil.copyfile(args.rules, raw / "rules.json")
        extras["rules_pin"] = _sha256(raw / "rules.json")
        commands.append("sha256sum raw/rules.json   # expect %s" % extras["rules_pin"][:8])

    summary = period_summary(entries, _date(args.since), _date(args.until, end=True))
    preface = Path(args.preface).read_text(encoding="utf-8") if getattr(args, "preface", None) else ""
    hashes = [[_sha256(p), "raw/" + p.name] for p in sorted(raw.iterdir()) if p.is_file()]
    md = render_markdown(summary, checks, title=args.title, prepared_by=args.prepared_by, generated_at=stamp, preface=preface,
                         commands=commands, extras=extras, hashes=hashes)
    report = out / "REPORT.md"
    report.write_text(md, encoding="utf-8")
    hashes.append([_sha256(report), "REPORT.md"])
    (out / "SHA256SUMS").write_text("".join("%s  %s\n" % (h, f) for h, f in hashes), encoding="utf-8")
    failed = [c for c in checks if c["accepted"] is False]
    for c in checks:
        print("%-4s %s: %s" % ({True: "ok", False: "FAIL", None: "note"}[c["accepted"]], c["check"], c["result"]))
    print("report: %s (%d entries in period; %d holds, %d released, %d declined, %d refused); %d raw file(s) hashed in SHA256SUMS"
          % (report, summary["entries"], summary["held"], summary["released"], summary["declined"], summary["refused"], len(hashes) - 1))
    return 1 if failed else 0
