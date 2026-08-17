# Description:
# Regenerates frameworks/allcontrols.json so that it contains every control
# found in the controls/ directory. This fixes drift where AllControls
# claims to contain "all the controls from all the frameworks" but is
# actually a hand-maintained, out-of-date subset.
#
# To use:
# Run from the repo root:
#   python3 scripts/generate_allcontrols.py
#
# This overwrites frameworks/allcontrols.json in place, preserving the
# framework's top-level metadata (name, description, attributes, etc.)
# and only regenerating the activeControls list.

import json
import os
import glob

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
controls_dir = os.path.join(repo_root, 'controls')
allcontrols_path = os.path.join(repo_root, 'frameworks', 'allcontrols.json')


def main():
    active_controls = []
    control_files = sorted(glob.glob(os.path.join(controls_dir, '*.json')))
    if not control_files:
        raise SystemExit(f"ERROR: no control files found in {controls_dir}")
    for filepath in control_files:
        with open(filepath) as f:
            control = json.load(f)
        active_controls.append({
            "controlID": control["controlID"],
            "patch": {
                "name": control["name"]
            }
        })

    active_controls = sorted(active_controls, key=lambda c: c["controlID"])

    seen = set()
    duplicates = set()
    for c in active_controls:
        cid = c["controlID"]
        if cid in seen:
            duplicates.add(cid)
        seen.add(cid)
    if duplicates:
        raise SystemExit(
            "ERROR: duplicate controlID(s) found across controls/*.json: "
            + ", ".join(sorted(duplicates))
            + ". Each control file must have a unique controlID."
        )

    with open(allcontrols_path) as f:
        framework = json.load(f)

    framework["activeControls"] = active_controls

    with open(allcontrols_path, "w") as f:
        json.dump(framework, f, indent=4)
        f.write("\n")

    print(f"AllControls regenerated with {len(active_controls)} controls.")


if __name__ == "__main__":
    main()
