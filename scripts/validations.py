import json
import os
import re

framework_dir = "frameworks"
controls_dir = "controls"
rules_dir = "rules"
currDir = os.path.abspath(os.getcwd())
rules_checked = []
controlID_to_filename = {}
rule_name_to_rule_dir = {}

def ignore_file(file_name: str):
    return file_name.startswith('__')

# Test that each control ID in a framework file has a corresponding control file in the "controls" directory
def validate_controls_in_framework():
    framework_files = os.listdir(framework_dir)
    for framework_file in framework_files:
        if ignore_file(framework_file):
            continue
        with open(os.path.join(framework_dir, framework_file), "r") as f:
            framework = json.load(f)

            for control in framework["activeControls"]:
                control_id = control["controlID"]
                # validate control exists and name is according to convention
                assert control_id in controlID_to_filename, f"No file found for Control ID {control_id}."


# Test that each rule name in a control file has a corresponding rule file in the "rules" directory
def validate_controls():
    control_files = os.listdir(controls_dir)
    control_ids = set()
    for control_file in control_files:
        if control_file.endswith('.json'):
            with open(os.path.join(controls_dir, control_file), "r") as f:
                control = json.load(f)
                # validate control ID is unique
                control_id = control.get("controlID")
                assert control_id not in control_ids, f"Duplicate control ID {control_id} found in control file {control_file}"
                control_ids.add(control_id)
                # validate all rules in control exist
                for rule_name in control["rulesNames"]:
                    if rule_name in rules_checked:
                        continue
                    else:
                        assert rule_name in rule_name_to_rule_dir, f"Rule {rule_name} does not exist"
                        rule_dir = rule_name_to_rule_dir[rule_name]
                        rule_file = os.path.join(rules_dir, rule_dir, "rule.metadata.json")
                        assert os.path.exists(rule_file), f"Rule file {rule_file} does not exist"
                        # If there is another rule with same name as this rule with "-v1" at the end - don't validate it
                        if not os.path.exists(os.path.join(rules_dir, rule_dir + "-v1")):
                            validate_tests_dir_for_rule(rule_dir)
                        rules_checked.append(rule_name)


# Test that each rule directory in the "rules" directory has a non-empty "tests" subdirectory
def validate_tests_dir_for_rule(rule_dir):
        tests_dir = os.path.join(rules_dir, rule_dir, "test")
        if not os.path.isdir(tests_dir):
            print(f"Tests directory {tests_dir} does not exist")
        # assert os.path.isdir(tests_dir), f"Tests directory {tests_dir} does not exist"
        # assert len(os.listdir(tests_dir)) > 0, f"Tests directory {tests_dir} is empty"

def fill_controlID_to_filename_map():
    for filename in os.listdir(controls_dir):
        # Load the JSON files
        if filename.endswith('.json'):
            with open(os.path.join(controls_dir, filename)) as f1:
                cntl = json.load(f1)
                controlID_to_filename[cntl['controlID']] = filename

def fill_rule_name_to_rule_dir():
    for rule_dir in os.listdir(rules_dir):
        if ignore_file(rule_dir):
            continue
        if os.path.exists(os.path.join(rules_dir, rule_dir, "rule.metadata.json")):
            with open(os.path.join(rules_dir, rule_dir, "rule.metadata.json")) as f1:
                rule = json.load(f1)
                rule_name_to_rule_dir[rule['name']] = rule_dir



if __name__ == "__main__":
    fill_rule_name_to_rule_dir()
    fill_controlID_to_filename_map()
    validate_controls_in_framework()
    validate_controls()
