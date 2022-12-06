import json
import csv
import os
import subprocess as s
from pathlib import Path
import copy
from typing import List

"""
Export rules controls and frameworks to files in json format
"""
currDir = os.path.abspath(os.getcwd())


control_rule_rows = []
framework_control_rows = []

def ignore_file(file_name: str):
    return file_name.startswith('__')

def export_json(data: dict, f_name:str, output_path: str):
    os.makedirs(output_path, exist_ok=True)
    with open(os.path.join(output_path, f"{f_name.lower()}"), "w") as f:
        f.write(json.dumps(data, indent=4))

def load_rules():
    p1 = os.path.join(currDir, 'rules') 
    regofile = 'raw.rego'
    filterregofile = 'filter.rego'
    rules_path = Path(p1).glob('**/*.json')
    loaded_rules = {}  # rules loaded from file system
    rules_list = []

    for path in rules_path:
        if ignore_file(path.parent.name):
            continue
        path_in_str = str(path)
        with open(path_in_str, "r") as f:
            new_rule = json.load(f)
        with open(os.path.join(os.path.dirname(path),regofile), 'r') as f:
            rule = f.read()
            if new_rule:
                new_rule["rule"] = rule
                try:
                    with open(os.path.join(os.path.dirname(path),filterregofile), 'r') as f:
                        filter_rego = f.read()
                        new_rule["resourceEnumerator"] = filter_rego
                except:
                    pass
        rules_list.append(new_rule)
        loaded_rules[new_rule['name']] = new_rule

    return loaded_rules, rules_list


def load_controls():

    p2 = os.path.join(currDir, 'controls') 
    controls_path = Path(p2).glob('**/*.json')
    loaded_controls = {}

    for path in controls_path:
        if ignore_file(path.name):
            print(path.name)
            continue
        path_in_str = str(path)

        with open(path_in_str, "r") as f:
            new_control = json.load(f)
        new_control["rules"] = []
        new_control_copy = copy.deepcopy(new_control)
        # del new_control["rulesNames"]  # remove rule names list from dict
        loaded_controls[new_control['name']] = new_control
        loaded_controls[new_control['name']]["filename"] = path.name

    return loaded_controls



def load_frameworks() -> dict:
    p3 = os.path.join(currDir, 'frameworks') 
    frameworks_path = Path(p3).glob('**/*.json')
    loaded_frameworks = {}
    frameworks_list = []

    for path in frameworks_path:
        if ignore_file(path.name):
            continue
        path_in_str = str(path)
        with open(path_in_str, "r") as f:
            new_framework = json.load(f)

        loaded_frameworks[new_framework['name']] = new_framework
        loaded_frameworks[new_framework['name']]["filename"] = path.name

    return loaded_frameworks


def convert_dotted_section_to_int(subsection_id : str, 
                                  subsection_digits : int = 2, 
                                  n_subsections : int = 3) -> int:
    """returns int representation of a dotted separated subsection string.

    Parameters
    ----------
    subsection_id : str
        A dotted subsection string - examples: 1.2, 2.3.12
        
    subsection_digits : int, optional
        The number of digits each subsection should have (default is 2)
        
    n_subsections : int, optional
        The number of expected subsections (default is 3)
        
    Returns
    ---------
    int
    
    Examples (with default values):
    ---------
    convert_dotted_section_to_int("1.1.12", 2, 3) = 01.01.12 = 10112
    convert_dotted_section_to_int("1.1.1", 2, 3)= 01.01.01 =  10101
    convert_dotted_section_to_int("1.2.1", 2, 3) = 01.02.01 =  10201
    
    convert_dotted_section_to_int("1.2", 3, 3)   = 001.002.000 =  1002000
    
    """
    
    if subsection_id == "":
        raise Exception("subsection_id string is empty")
    
    subsection_ids = subsection_id.split(".")
    
    res = ""
    
    # iterate each subsection
    for subsection in subsection_ids:
        current_subsection_id = subsection
        
        # identify the the subsection range and add "0"s to prefix if needed.
        for i in range(1, subsection_digits):
            if int(subsection) < 10**i:
                current_subsection_id = "0"*(subsection_digits-i) + current_subsection_id
                break
            
        res = res + current_subsection_id
    
    # if there are missing subsections, add "0"s to the right of the int
    if n_subsections > len(subsection_ids):
        res = res + "0"*subsection_digits*(n_subsections - len(subsection_ids))
        
    return int(res)
