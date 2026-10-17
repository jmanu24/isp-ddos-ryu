"""Formats the KPM samples of the mobile actuation test.

stdin: JSON list (plain or base64-encoded) of {"phase","t","prb_ul","thp_ul","thp_dl","age"} rows.
  (no args)  -> a text table, one line per sample, grouped by phase
  --stats    -> one JSON object: {phase: {"n", "thp_ul", "prb_ul"}} averaged
                over the samples that carry a value (None when there are none)
"""
import base64
import json
import sys

PHASES = ["idle", "before", "during", "after"]


def _avg(values):
    values = [float(v) for v in values if v is not None]
    return round(sum(values) / len(values), 1) if values else None


def stats(rows):
    out = {}
    for phase in PHASES:
        mine = [r for r in rows if r["phase"] == phase and r.get("thp_ul") is not None]
        out[phase] = {"n": len(mine), "thp_ul": _avg(r["thp_ul"] for r in mine),
                      "prb_ul": _avg(r["prb_ul"] for r in mine)}
    return out


def table(rows):
    def cell(v, width):
        return str("-" if v is None else v).rjust(width)
    lines = ["phase    t(s)  PrbUsedUl  UEThpUl(kbps)  UEThpDl(kbps)  age(s)"]
    for r in rows:
        lines.append("%-8s %s  %s  %s  %s  %s" % (
            r["phase"], cell(r["t"], 5), cell(r["prb_ul"], 9), cell(r["thp_ul"], 13),
            cell(r["thp_dl"], 13), cell(r["age"], 6)))
    return lines


if __name__ == "__main__":
    raw = sys.stdin.read().strip()
    # Ansible would turn a JSON-looking stdin string back into a Python list
    # (single-quoted repr), so the playbook passes it base64-encoded.
    if not raw.startswith("["):
        raw = base64.b64decode(raw).decode()
    data = json.loads(raw)
    if "--stats" in sys.argv:
        print(json.dumps(stats(data)))
    else:
        print("\n".join(table(data)))
