import json
import csv
import os
import subprocess as s
from pathlib import Path
import copy

"""
Export rules controls and frameworks to files in json format
"""
currDir = os.path.abspath(os.getcwd())

control_rule_rows = []
framework_control_rows = []

def load_rules():
    p1 = os.path.join(currDir, 'rules') 
    regofile = 'raw.rego'
    rules_path = Path(p1).glob('**/*.json')
    loaded_rules = {}  # rules loaded from file system
    rules_list = []

    for path in rules_path:
        path_in_str = str(path)
        with open(path_in_str, "r") as f:
            new_rule = json.load(f)

        pos = path_in_str.rfind('/')
        with open(path_in_str[:pos + 1] + regofile, 'r') as f:
            rule = f.read()
            if new_rule:
                new_rule["rule"] = rule
                if "resourceCount" in new_rule:
                    new_rule["resourceEnumerator"] = get_rego_for_resource_count(new_rule["resourceCount"])
        rules_list.append(new_rule) 
        loaded_rules[new_rule['name']] = new_rule

    return loaded_rules, rules_list


def load_controls(loaded_rules: dict):
    p2 = os.path.join(currDir, 'controls') 
    controls_path = Path(p2).glob('**/*.json')
    loaded_controls = {}
    controls_list = []

    for path in controls_path:
        path_in_str = str(path)

        with open(path_in_str, "r") as f:
            new_control = json.load(f)
        new_control["rules"] = []
        new_control_copy = copy.deepcopy(new_control)
        controls_list.append(new_control_copy)

        for rule_name in new_control["rulesNames"]:
            if rule_name in loaded_rules:
                new_control["rules"].append(loaded_rules[rule_name])
                new_row = [new_control['id'], rule_name] # TODO : change 'id' to 'controlID'
                control_rule_rows.append(new_row)

        del new_control["rulesNames"]  # remove rule names list from dict
        loaded_controls[new_control['name']] = new_control

    return loaded_controls, controls_list


def load_frameworks(loaded_controls: dict):
    p3 = os.path.join(currDir, 'frameworks') 
    frameworks_path = Path(p3).glob('**/*.json')
    loaded_frameworks = {}
    frameworks_list = []

    for path in frameworks_path:
        path_in_str = str(path)
        with open(path_in_str, "r") as f:
            new_framework = json.load(f)
        new_framework["controls"] = []
        new_framework_copy = copy.deepcopy(new_framework)
        frameworks_list.append(new_framework_copy)

        for control_name in new_framework["controlsNames"]:
            if control_name in loaded_controls:
                new_framework["controls"].append(loaded_controls[control_name])
                new_row = [new_framework['name'], loaded_controls[control_name]['id'], control_name] # TODO : change 'id' to 'controlID'
                framework_control_rows.append(new_row)

        del new_framework["controlsNames"]
        loaded_frameworks[new_framework['name']] = new_framework

    return loaded_frameworks, frameworks_list

def validate_controls():
    p4 = os.path.join(currDir, 'controls') 
    controls_path = list(Path(p4).glob('**/*.json'))
    set_of_ids = set()

    for path in  controls_path:
        path_in_str = str(path)

        with open(path_in_str, "r") as f:
            new_control = json.load(f)
        
        set_of_ids.add(int(new_control["id"][2:]))

    sum_of_controls = len(controls_path)
    if sum_of_controls != len(set_of_ids):
        raise Exception("Error validate the numbers of controls, {} != {}".format(sum_of_controls ,len(set_of_ids)))


def get_rego_for_resource_count(count_type):
    with open(os.path.join(currDir, 'resource-counters' , count_type + '.rego'), 'r') as f:
        rego = f.read()
    return rego


def export_json(data: dict, f_name:str, output_path: str):
    os.makedirs(output_path, exist_ok=True)
    with open(os.path.join(output_path, f"{f_name.lower()}.json"), "w") as f:
        f.write(json.dumps(data, indent=4))


def create_cvs_file(header, rows, filename, output_path):
    os.makedirs(output_path, exist_ok=True)
    with open(os.path.join(output_path, f"{filename}.csv"), 'w', encoding='UTF8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)


if __name__ == '__main__':
    rules, rules_list = load_rules()
    controls, controls_list = load_controls(loaded_rules=rules)
    validate_controls()
    frameworks, frameworks_list = load_frameworks(loaded_controls=controls)

    # create full framework json files
    # TODO - delete when kubescape works with csv files
    for k, v in frameworks.items():
        export_json(data=v, f_name=k, output_path="release")

    # create object jsons - frameworks, controls, rules
    export_json(frameworks_list, 'frameworks', "release")
    export_json(controls_list, 'controls', "release")
    export_json(rules_list, 'rules', "release")

    # file 1 - 'ControlID', 'RuleName'
    header1 = ['ControlID', 'RuleName']
    create_cvs_file(header1, control_rule_rows, 'ControlID_RuleName', "release")

    # file 2 - frameworkName, ControlID, ControlName
    header2 = ['frameworkName', 'ControlID', 'ControlName']
    create_cvs_file(header2, framework_control_rows, 'FWName_CID_CName', "release")
