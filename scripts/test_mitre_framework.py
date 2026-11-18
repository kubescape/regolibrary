#!/usr/bin/env python3
"""Regression checks for the issue #288 MITRE membership and export contract."""

import csv
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
# Snapshot at audit commit 01585762365e270a437e3cad490d80f21c2f968b,
# unchanged at implementation baseline 90ab89544107e8cd0d54f6006c5731114136f531.
BASELINE = ROOT / "scripts/testdata/mitre-before-288.json"
# Reviewed in https://github.com/kubescape/regolibrary/issues/288#issuecomment-6359417377.
# Keep this independent of activeControls: a count alone cannot detect substitutions.
EXPECTED_IDS = """
C-0002 C-0007 C-0012 C-0013 C-0014 C-0015 C-0016 C-0017 C-0020
C-0021 C-0026 C-0030 C-0031 C-0034 C-0035 C-0036 C-0037 C-0038
C-0039 C-0041 C-0042 C-0045 C-0046 C-0048 C-0052 C-0053 C-0054
C-0057 C-0058 C-0059 C-0066 C-0067 C-0069 C-0070 C-0074 C-0078
C-0084 C-0088 C-0113 C-0127 C-0173 C-0175 C-0188 C-0191 C-0193
C-0197 C-0210 C-0262 C-0263 C-0268 C-0269 C-0270 C-0271 C-0279
C-0281 C-0282 C-0306
""".split()
EXPECTED_CHANGED_ARTIFACTS = {
    "mitre.json", "frameworks.json", "FWName_CID_CName.csv", "controls.json"
}


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def without_fields(value, *fields):
    return {key: item for key, item in value.items() if key not in fields}


class MitreFrameworkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = read_json(ROOT / "frameworks/mitre.json")
        cls.before = read_json(BASELINE)
        cls.canonical = {
            control["controlID"]: control
            for path in (ROOT / "controls").glob("*.json")
            if not path.name.startswith("__")
            for control in [read_json(path)]
        }
        cls.old_ids = {entry["controlID"] for entry in cls.before["activeControls"]}
        cls.added_ids = set(EXPECTED_IDS) - cls.old_ids

        temporary = tempfile.TemporaryDirectory(prefix="regolibrary-mitre-test-")
        cls.addClassCleanup(temporary.cleanup)
        work = Path(temporary.name)
        source = work / "source"
        source.mkdir()
        # Both exports use this same tree and enumeration order. Only mitre.json
        # changes; no network, Git checkout, or release-directory writes are needed.
        for directory in ("rules", "controls", "frameworks", "categories",
                          "attack-tracks", "exceptions"):
            shutil.copytree(ROOT / directory, source / directory)
        shutil.copy2(ROOT / "default-config-inputs.json", source)
        (source / "scripts").mkdir()
        shutil.copy2(ROOT / "scripts/export.py", source / "scripts/export.py")
        cls.exports = []
        for label, content in (("before", BASELINE.read_bytes()),
                               ("after", (ROOT / "frameworks/mitre.json").read_bytes())):
            (source / "frameworks/mitre.json").write_bytes(content)
            output = work / label
            env = {**os.environ, "OUTPUT": str(output), "RELEASE": "test-mitre-288"}
            result = subprocess.run(
                [sys.executable, "scripts/export.py"], cwd=source, env=env,
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode:
                raise RuntimeError(f"{label} export failed:\n{result.stdout}\n{result.stderr}")
            cls.exports.append(output)

    def indexed(self, entries, key):
        indexed = {entry[key]: entry for entry in entries}
        self.assertEqual(len(indexed), len(entries), f"Duplicate {key}")
        return indexed

    def assert_membership(self, framework):
        self.assertEqual(framework["ControlsIDs"], EXPECTED_IDS)
        self.assertEqual([c["controlID"] for c in framework["controls"]], EXPECTED_IDS)
        for control in framework["controls"]:
            self.assertEqual(control["name"], self.canonical[control["controlID"]]["name"])

    def test_exact_source_membership_and_names(self):
        actual = [entry["controlID"] for entry in self.source["activeControls"]]
        self.assertEqual(len(EXPECTED_IDS), 57)
        self.assertEqual(EXPECTED_IDS, sorted(set(EXPECTED_IDS)))
        self.assertEqual(actual, EXPECTED_IDS)
        self.assertEqual(len(self.old_ids), 27)
        self.assertEqual(len(self.old_ids & set(actual)), 26)
        self.assertEqual(len(self.added_ids), 31)
        self.assertEqual(self.old_ids - set(actual), {"C-0068"})
        for entry in self.source["activeControls"]:
            self.assertEqual(entry["patch"], {
                "name": self.canonical[entry["controlID"]]["name"]
            })

    def test_framework_identity_and_description(self):
        self.assertEqual(
            without_fields(self.source, "description", "activeControls"),
            without_fields(self.before, "description", "activeControls"),
        )
        self.assertEqual(self.source["name"], "MITRE")
        self.assertIn("https://microsoft.github.io/Threat-Matrix-for-Kubernetes/",
                      self.source["description"])
        self.assertNotIn("2020/04/k8s-matrix.png", self.source["description"])

    def test_exported_membership_and_retained_controls(self):
        before, after = [read_json(path / "mitre.json") for path in self.exports]
        self.assert_membership(after)
        self.assertEqual(after["description"], self.source["description"])
        self.assertEqual(without_fields(after, "description", "controls", "ControlsIDs"),
                         without_fields(before, "description", "controls", "ControlsIDs"))
        old_controls = self.indexed(before["controls"], "controlID")
        new_controls = self.indexed(after["controls"], "controlID")
        for control_id in self.old_ids & set(EXPECTED_IDS):
            self.assertEqual(new_controls[control_id], old_controls[control_id], control_id)

    def test_only_expected_artifacts_change(self):
        before, after = self.exports
        files = {path.name for path in before.iterdir()}
        self.assertEqual(files, {path.name for path in after.iterdir()})
        changed = {name for name in files
                   if (before / name).read_bytes() != (after / name).read_bytes()}
        self.assertEqual(changed, EXPECTED_CHANGED_ARTIFACTS)

    def test_aggregate_frameworks(self):
        before, after = [self.indexed(read_json(path / "frameworks.json"), "name")
                         for path in self.exports]
        self.assertEqual(before.keys(), after.keys())
        for name in before:
            if name != "MITRE":
                self.assertEqual(after[name], before[name], name)
        self.assert_membership(after["MITRE"])
        self.assertEqual(after["MITRE"]["description"], self.source["description"])
        self.assertEqual(
            without_fields(after["MITRE"], "description", "controls", "ControlsIDs"),
            without_fields(before["MITRE"], "description", "controls", "ControlsIDs"),
        )
        old_controls = self.indexed(before["MITRE"]["controls"], "controlID")
        new_controls = self.indexed(after["MITRE"]["controls"], "controlID")
        for control_id in self.old_ids & set(EXPECTED_IDS):
            self.assertEqual(new_controls[control_id], old_controls[control_id], control_id)

    def test_exact_reverse_membership_changes(self):
        before, after = [self.indexed(read_json(path / "controls.json"), "controlID")
                         for path in self.exports]
        self.assertEqual(before.keys(), after.keys())
        changed = set()
        for control_id, old_control in before.items():
            control = after[control_id]
            self.assertEqual(without_fields(control, "frameworks"),
                             without_fields(old_control, "frameworks"), control_id)
            expected = set(old_control["frameworks"])
            if control_id in self.added_ids:
                self.assertNotIn("MITRE", expected, control_id)
                expected.add("MITRE")
            elif control_id == "C-0068":
                self.assertIn("MITRE", expected)
                expected.remove("MITRE")
            self.assertEqual(control["frameworks"], sorted(expected), control_id)
            if control != old_control:
                changed.add(control_id)
        self.assertEqual(changed, self.added_ids | {"C-0068"})
        self.assertEqual(len(changed), 32)
        self.assertIn("C-0068", after)

    def test_csv_membership_and_unrelated_rows(self):
        rows = []
        for path in self.exports:
            with (path / "FWName_CID_CName.csv").open(encoding="utf-8", newline="") as stream:
                rows.append(list(csv.reader(stream)))
        before, after = rows
        self.assertEqual(after[0], ["frameworkName", "ControlID", "ControlName"])
        self.assertEqual(before[0], after[0])
        self.assertEqual([row for row in before[1:] if row[0] != "MITRE"],
                         [row for row in after[1:] if row[0] != "MITRE"])
        self.assertEqual([row for row in after[1:] if row[0] == "MITRE"], [
            ["MITRE", control_id, self.canonical[control_id]["name"]]
            for control_id in EXPECTED_IDS
        ])


if __name__ == "__main__":
    unittest.main(verbosity=2)
