import json
import csv
import os
from pathlib import Path

"""
Update csv files
"""
currDir = os.path.abspath(os.getcwd())

loaded_rule_names = []
loaded_controls = {}
control_rule_rows = []
framework_control_rows = []

def ignore_file(file_name: str):
    return file_name.startswith('__')

def ignore_file_rule(path: str):
    # ignore expected.json files
    if path.parent.parent.name == "test":
        return True
    # ignore test input files
    elif path.parent.parent.parent.name == "test":
        return True
    elif path.parent.name.startswith('__'):
        return True
    return False


def load_rules():
    p1 = os.path.join(currDir, 'rules') 
    rules_path = Path(p1).glob('**/*.json')
    for path in rules_path:
        if ignore_file_rule(path):
            continue
        path_in_str = str(path)
        with open(path_in_str, "r") as f:
            new_rule = json.load(f)
        loaded_rule_names.append(new_rule['name'])


def load_controls():
    p2 = os.path.join(currDir, 'controls') 
    controls_path = Path(p2).glob('**/*.json')
    for path in controls_path:
        if ignore_file(path.name):
            continue
        path_in_str = str(path)
        with open(path_in_str, "r") as f:
            new_control = json.load(f)
        loaded_controls[new_control['name']] = new_control
        for rule_name in new_control["rulesNames"]:
            if rule_name in loaded_rule_names:
                control_rule_rows.append([new_control['controlID'], rule_name])


def load_frameworks():
    p3 = os.path.join(currDir, 'frameworks') 
    frameworks_path = Path(p3).glob('**/*.json')
    for path in frameworks_path:
        if ignore_file(path.name):
            continue
        path_in_str = str(path)
        with open(path_in_str, "r") as f:
            new_framework = json.load(f)
        for control_name in new_framework["controlsNames"]:
            if control_name in loaded_controls:
                new_row = [new_framework['name'], loaded_controls[control_name]['controlID'], control_name]
                framework_control_rows.append(new_row)


def create_cvs_file(header, rows, filename):
    with open(f"{filename}.csv", 'w', encoding='UTF8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(header)
        rows = sorted(rows, key=lambda x: ''.join(x))
        writer.writerows(rows)


if __name__ == '__main__':
    load_rules()
    load_controls()
    load_frameworks()

    # file 1 - 'ControlID', 'RuleName'
    header1 = ['ControlID', 'RuleName']
    create_cvs_file(header1, control_rule_rows, 'ControlID_RuleName')

    # file 2 - frameworkName, ControlID, ControlName
    header2 = ['frameworkName', 'ControlID', 'ControlName']
    create_cvs_file(header2, framework_control_rows, 'FWName_CID_CName')
