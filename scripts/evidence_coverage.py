# Reports which rules emit real, resolvable evidence paths and which emit placeholders.
#
# Every rule returns its findings as an object containing "alertMessage", alongside
# up to four path fields: failedPaths, reviewPaths, deletePaths and fixPaths. A path
# is either computed at evaluation time (sprintf, a variable, or a literal string) or
# a literal empty list, which carries no information for anything downstream that
# tries to resolve it.
#
# This walks rules/*/raw.rego and classifies each one without evaluating any rego.
# Run from the repository root:
#
#     python ./scripts/evidence_coverage.py            # summary
#     python ./scripts/evidence_coverage.py --json out.json
#
# See https://github.com/kubescape/regolibrary/issues/769 for the numbers this
# reproduces and why they matter.

import argparse
import csv
import json
import os
from collections import Counter

RULES_DIR = "rules"
CONTROL_RULE_CSV = "ControlID_RuleName.csv"

PATH_KEYS = ("failedPaths", "reviewPaths", "deletePaths", "fixPaths")

REAL = "real"
PLACEHOLDER = "placeholder"
ABSENT = "absent"

# A rule is treated as credential-bearing when its controlConfigInputs reference
# either of these posture control inputs. See section 5.4 of the evidence-of-finding
# proposal in kubescape/designs-and-proposals.
REDACTION_INPUTS = (
    "settings.postureControlInputs.sensitiveValues",
    "settings.postureControlInputs.sensitiveKeyNames",
)


def ignore_file(file_name: str):
    return file_name.startswith('__')


def strip_comments(src: str):
    # Drop "#" comments without touching a "#" that sits inside a string literal.
    out = []
    in_str = in_raw = esc = False
    i = 0
    while i < len(src):
        c = src[i]
        if in_str:
            out.append(c)
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
        elif in_raw:
            out.append(c)
            if c == "`":
                in_raw = False
        elif c == '"':
            in_str = True
            out.append(c)
        elif c == "`":
            in_raw = True
            out.append(c)
        elif c == "#":
            while i < len(src) and src[i] != "\n":
                i += 1
            continue
        else:
            out.append(c)
        i += 1
    return "".join(out)


def object_literals(src: str):
    # Spans of every balanced {...}, respecting string literals.
    spans = []
    stack = []
    in_str = in_raw = esc = False
    for i, c in enumerate(src):
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            continue
        if in_raw:
            if c == "`":
                in_raw = False
            continue
        if c == '"':
            in_str = True
        elif c == "`":
            in_raw = True
        elif c == "{":
            stack.append(i)
        elif c == "}" and stack:
            spans.append((stack.pop(), i + 1))
    return spans


def top_level_entries(body: str):
    # Split "key: value" pairs, keeping nested {} [] () and strings intact so that
    # fixPaths entries such as [{"path": p, "value": v}] stay in one piece.
    entries = []
    cur = []
    depth = 0
    in_str = in_raw = esc = False
    for c in body:
        if in_str:
            cur.append(c)
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            continue
        if in_raw:
            cur.append(c)
            if c == "`":
                in_raw = False
            continue
        if c == '"':
            in_str = True
            cur.append(c)
            continue
        if c == "`":
            in_raw = True
            cur.append(c)
            continue
        if c in "{[(":
            depth += 1
        elif c in "}])":
            depth -= 1
        if c == "," and depth == 0:
            entries.append("".join(cur))
            cur = []
        else:
            cur.append(c)
    if cur:
        entries.append("".join(cur))
    return entries


def classify_alert(text: str):
    result = {}
    for entry in top_level_entries(text[1:-1]):
        stripped = entry.strip()
        for key in PATH_KEYS:
            prefix = '"%s"' % key
            if not stripped.startswith(prefix):
                continue
            rest = stripped[len(prefix):].lstrip()
            if rest.startswith(":"):
                value = rest[1:].strip()
                result[key] = PLACEHOLDER if value == "[]" else REAL
    return result


def alert_blocks(rule_dir: str):
    raw_path = os.path.join(RULES_DIR, rule_dir, "raw.rego")
    with open(raw_path, encoding="utf-8", errors="replace") as handle:
        src = strip_comments(handle.read())

    blocks = []
    claimed = []
    for start, end in sorted(object_literals(src), key=lambda s: (s[0], -s[1])):
        if any(start >= cs and end <= ce for cs, ce in claimed):
            continue
        text = src[start:end]
        if not any(e.strip().startswith('"alertMessage"') for e in top_level_entries(text[1:-1])):
            continue
        claimed.append((start, end))
        blocks.append(classify_alert(text))
    return blocks


def rollup(blocks, key):
    seen = [b[key] for b in blocks if key in b]
    if not seen:
        return ABSENT
    if all(v == REAL for v in seen):
        return "always_real"
    if all(v == PLACEHOLDER for v in seen):
        return "placeholder"
    return "mixed"


def is_real(value):
    return value in ("always_real", "mixed")


def load_control_map():
    mapping = {}
    if not os.path.exists(CONTROL_RULE_CSV):
        return mapping
    with open(CONTROL_RULE_CSV, newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            control_id = (row.get("ControlID") or "").strip()
            rule_name = (row.get("RuleName") or "").strip()
            if control_id and rule_name:
                mapping.setdefault(rule_name, set()).add(control_id)
    return {name: sorted(ids) for name, ids in mapping.items()}


def redaction_inputs(rule_dir: str):
    meta_path = os.path.join(RULES_DIR, rule_dir, "rule.metadata.json")
    if not os.path.exists(meta_path):
        return []
    try:
        with open(meta_path, encoding="utf-8") as handle:
            meta = json.load(handle)
    except (json.JSONDecodeError, OSError):
        return []
    used = [entry.get("path") for entry in meta.get("controlConfigInputs") or []]
    return sorted({p for p in used if p in REDACTION_INPUTS})


def build_report():
    control_map = load_control_map()
    rules = []

    for rule_dir in sorted(os.listdir(RULES_DIR)):
        if ignore_file(rule_dir):
            continue
        if not os.path.isfile(os.path.join(RULES_DIR, rule_dir, "raw.rego")):
            continue

        blocks = alert_blocks(rule_dir)
        per_key = {key: rollup(blocks, key) for key in PATH_KEYS}
        rules.append({
            "rule": rule_dir,
            "controls": control_map.get(rule_dir, []),
            "alertBlocks": len(blocks),
            "failedPaths": per_key["failedPaths"],
            "reviewPaths": per_key["reviewPaths"],
            "deletePaths": per_key["deletePaths"],
            "fixPaths": per_key["fixPaths"],
            "emitsAnyRealPath": any(is_real(v) for v in per_key.values()),
            "redactionInputs": redaction_inputs(rule_dir),
        })

    buckets = Counter(rule["failedPaths"] for rule in rules)
    any_real = [rule for rule in rules if rule["emitsAnyRealPath"]]
    no_real_failed = [rule for rule in rules if not is_real(rule["failedPaths"])]
    fix_only = [
        rule for rule in no_real_failed
        if not is_real(rule["reviewPaths"])
        and not is_real(rule["deletePaths"])
        and is_real(rule["fixPaths"])
    ]

    return {
        "totalRules": len(rules),
        "failedPathsBuckets": {
            "alwaysReal": buckets.get("always_real", 0),
            "mixed": buckets.get("mixed", 0),
            "placeholderOnly": buckets.get("placeholder", 0),
            "absent": buckets.get(ABSENT, 0),
        },
        "rulesEmittingAnyRealPath": len(any_real),
        "rulesWithNoPathEvidence": len(rules) - len(any_real),
        "rulesRescuedByOtherPathKinds": len([r for r in no_real_failed if r["emitsAnyRealPath"]]),
        "rulesWhereOnlyFixPathsAreReal": len(fix_only),
        "realPathsByKind": {key: len([r for r in rules if is_real(r[key])]) for key in PATH_KEYS},
        "redactionPredicateRules": [r["rule"] for r in rules if r["redactionInputs"]],
        "rules": rules,
    }


def print_summary(report):
    buckets = report["failedPathsBuckets"]
    total = report["totalRules"]

    print("rules analysed                      : %d" % total)
    print("failedPaths always real             : %d" % buckets["alwaysReal"])
    print("failedPaths mixed                   : %d" % buckets["mixed"])
    print("failedPaths placeholder only        : %d" % buckets["placeholderOnly"])
    print("failedPaths absent                  : %d" % buckets["absent"])
    print("emit at least one real path         : %d / %d" % (report["rulesEmittingAnyRealPath"], total))
    print("emit no path evidence at all        : %d / %d" % (report["rulesWithNoPathEvidence"], total))
    print("no real failedPaths, rescued by kind: %d" % report["rulesRescuedByOtherPathKinds"])
    print("only fixPaths are real              : %d" % report["rulesWhereOnlyFixPathsAreReal"])
    print()
    print("real paths by kind:")
    for key, count in report["realPathsByKind"].items():
        print("  %-12s %d" % (key, count))
    print()
    print("match the redaction predicate: %s" % ", ".join(report["redactionPredicateRules"]))


def main():
    parser = argparse.ArgumentParser(description="Report evidence-path coverage across the rule library")
    parser.add_argument("--json", dest="json_out", help="also write the full per-rule report here")
    args = parser.parse_args()

    if not os.path.isdir(RULES_DIR):
        raise SystemExit("run this from the repository root: %s/ not found" % RULES_DIR)

    report = build_report()
    print_summary(report)

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)
            handle.write("\n")
        print("\nwrote %s" % args.json_out)


if __name__ == "__main__":
    main()
