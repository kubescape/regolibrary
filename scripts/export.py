"""
export.py script perform the following: 
    1. converts all REGOLIBRARY rules / controls / frameworks into Json/CSV file/s format (for release process and integration with Kubescape)
    2. Generating attack-chain data and configurations.
This file is part of the GitHub Action pipeline for testing and release process
"""

import json
import csv
import os
import copy
import logging
from pathlib import Path
from typing import List

__CWD__ = os.path.abspath(os.getcwd())  # current working dir
__CONTROL_RULE_ROWS__ = []
__FRAMEWORK_CONTROL_ROWS__ = []
__SUBSECTION_TREE_SEPARATOR__ = '.'


"""
:return True if file needs to be skipped (start with '__') otherwise False 
"""
def ignore_file(file_name: str):
    if file_name.startswith('__'):
        logging.info(f"Skipping file '{file_name}'")
        return True
    else:
        return False 

"""function check if path's needs to be skipped. skipping: (expected.json files / test input files / files starting with '__')
:return True if file needs to be skipped otherwise False 
"""
def ignore_file_rule(path: str):
    # ignore expected.json files
    if path.parent.parent.name == "test":
        logging.info(f"Skipping test partent file '{path}'")
        return True
    # ignore test input files
    elif path.parent.parent.parent.name == "test":
        logging.info(f"Skipping test partent file '{path}'")
        return True
    elif path.parent.name.startswith('__'):
        logging.info(f"Skipping file '{path}'")
        return True
    return False

""" function is loading all rules & rulenames found at the directory. 
:return list of all rules loaded and scanned
"""
def load_rules():
    
    p1 = os.path.join(__CWD__, 'rules')  # read 'rules' dir
    logging.info(f"Loading rules from folder '{p1}'")
    
    regofile = 'raw.rego'
    filterregofile = 'filter.rego'
    rules_path = Path(p1).glob('**/*.json')
    loaded_rules = {}  # rules loaded from file system
    rules_list = []

    for path in rules_path:
        if ignore_file_rule(path):
            continue
        path_in_str = str(path)
        try:
            with open(path_in_str, "r") as f:
                new_rule = json.load(f)
        except Exception as e:
            logging.exception(f"failed to read rule '{f}'")
            raise Exception(e)

        try:
            with open(os.path.join(os.path.dirname(path),regofile), 'r') as f:
                rule = f.read()
                if new_rule:
                    new_rule["rule"] = rule
                    try:
                        with open(os.path.join(os.path.dirname(path),filterregofile), 'r') as f:
                            filter_rego = f.read()
                            new_rule["resourceEnumerator"] = filter_rego
                    # skip filter.rego files which do not need to be presented at the folder
                    except FileNotFoundError as e:
                        pass
                    except Exception as e1:
                        raise TypeError(f"Failed to read rego-filter file: '{os.path.join(os.path.dirname(path),filterregofile)}' with error '{e1}'")
        except Exception as e:
            raise TypeError(f"Failed to read rego file: '{os.path.join(os.path.dirname(path),regofile)}'")

        rules_list.append(new_rule)
        loaded_rules[new_rule['name']] = new_rule

    return loaded_rules, rules_list


""" function is loading all contros found at the directory. 
:return list/json of all controls loaded and scanned
"""
def load_controls(loaded_rules: dict):

    p2 = os.path.join(__CWD__, 'controls')
    logging.info(f"Loading controls from folder '{p2}'")

    controls_path = Path(p2).glob('**/*.json')
    loaded_controls = {}
    controls_list = []

    for path in controls_path:
        if ignore_file(path.name):  # check if file needs to be ignored 
            continue
        path_in_str = str(path)

        try: 
            with open(path_in_str, "r") as f:
                new_control = json.load(f)
        except Exception as e:
            logging.error(f"failed to open control: '{path_in_str}'")
            raise TypeError(e)
        
        new_control["rules"] = []
        new_control_copy = copy.deepcopy(new_control)
        controls_list.append(new_control_copy)

        for rule_name in new_control["rulesNames"]:
            if rule_name in loaded_rules:
                new_control["rules"].append(loaded_rules[rule_name])
                new_row = [new_control['controlID'], rule_name] 
                __CONTROL_RULE_ROWS__.append(new_row)
            else:
                raise TypeError("Error in ruleNames of control '{0}', rule '{1}' does not exist".format(new_control["name"], rule_name))

        del new_control["rulesNames"]  # remove rule names list from dict
        loaded_controls[new_control['controlID']] = new_control

    return loaded_controls, controls_list

"""
WARNING: recursive call
Recursively iterate over framework subsection and adds the tree info as `id` attribute to the section
"""
def add_subsections_ids(parents: list, sections: dict):
        
    for section_id, section in sections.items():
        section_full_id = parents.copy()
        section_full_id.append(section_id)
        section['id'] = __SUBSECTION_TREE_SEPARATOR__.join(section_full_id)
        add_subsections_ids(section_full_id, section.get('subSections', {}))

"""updating patch keys for all controls
:return updated controls dict
"""
def patch_control(control:dict, patch: dict, force_patch = True) -> dict:
    logging.info(f"Patching control key '{patch['name']}'")

    for key in patch:
        if not force_patch:
            if key not in control.keys():
                raise TypeError(f"control {control['controlID']} doesnt have patch key {key}")

        control[key] = patch[key]
    
    return control


"""function is loading all frameworks found at the directory.
:return list of all frameworks loaded and scanned
"""
def load_frameworks(loaded_controls: dict):
    p3 = os.path.join(__CWD__, 'frameworks')
    logging.info(f"Loading frameworks from folder '{p3}'")
 
    frameworks_path = Path(p3).glob('**/*.json')
    loaded_frameworks = {}
    frameworks_list = []

    # update framework objects 
    for path in frameworks_path:
        
        # skip irrelevant files
        if ignore_file(path.name):
            continue
        
        # load frameworks file
        try:
            path_in_str = str(path)
            with open(path_in_str, "r") as f:
                new_framework = json.load(f)
        except Exception as e:
            logging.error(f"Cannot open path '{path_in_str}'")
            raise TypeError(e)
        # adding new attributes to frameowrk json
        new_framework["version"] = os.getenv("RELEASE")
        new_framework["controls"] = []
        new_framework["ControlsIDs"] = []
    
        # use case 
        for control_framework in new_framework["activeControls"]:
            controlID = control_framework["controlID"]
        
            if controlID in loaded_controls:
                base_control_name = loaded_controls[controlID]["name"]
                tmp_control = copy.deepcopy(patch_control(copy.deepcopy(loaded_controls[controlID]), control_framework["patch"]))
                new_framework["controls"].append(tmp_control)
                new_framework["ControlsIDs"].append(tmp_control['controlID'])
                new_row = [new_framework['name'], controlID, base_control_name] 
                __FRAMEWORK_CONTROL_ROWS__.append(new_row)
            else:
                raise TypeError(f"Error in activeControls of framework '{new_framework['name']}' control id '{controlID}' does not exist")
        
        logging.info("Adding subsection IDs")
        add_subsections_ids([], new_framework.get('subSections', {}))

        new_framework_copy = copy.deepcopy(new_framework)
        frameworks_list.append(new_framework_copy)

        del new_framework["activeControls"]
        del new_framework_copy["activeControls"]
        loaded_frameworks[new_framework['name']] = new_framework
    
    # drop "rules" from frameworks list (frameworks.json)
    for framework in frameworks_list:
        for control in framework["controls"]:
           control["rules"] = []

    return loaded_frameworks, frameworks_list


"""function loads all files from attach-tracks folder and return it's output as json/dict
:return json format with attack tracks data
"""
def load_attack_tracks():
    p3 = os.path.join(__CWD__, 'attack-tracks')
    logging.info(f"Loading attack tracks from path: '{p3}'")
    
    attack_tracks_path = Path(p3).glob('**/*.json')
    loaded_attack_tracks = {}

    for path in attack_tracks_path:
        if ignore_file(path.name):
            continue
        path_in_str = str(path)
        
        try:
            with open(path_in_str, "r") as f:
                new_attack_track = json.load(f) 
        except Exception as e:
            logging.error(f"Failed to open path: '{path_in_str}'.")
            raise TypeError(e)
        new_attack_track["spec"]["version"] = os.getenv("RELEASE")
        loaded_attack_tracks[new_attack_track['metadata']['name']] = new_attack_track

    return list(loaded_attack_tracks.values())


"""function validates that all controls under controls path folder added object 'controlID' successfully
:raise error if validation did not succeeded. 
"""
def validate_controls():
    p4 = os.path.join(__CWD__, 'controls') 
    logging.info(f"Validating controls from folder '{p4}'")

    controls_path = list(Path(p4).glob('**/*.json'))
    set_of_ids = set()

    for path in controls_path:
        path_in_str = str(path)

        try:
            with open(path_in_str, "r") as f:
                new_control = json.load(f)
        except Exception as e:
            logging.error(f"Failed to open control: '{path_in_str}'")
            raise Exception(e)
        set_of_ids.add(new_control["controlID"])

    if len(controls_path) != len(set_of_ids):
        raise TypeError(f"Failed to validate the controls number from folder '{p4}'. Counted from path: '{len(controls_path)}' But actually received: '{len(set_of_ids)}'")  
        
"""load default config json file
:return json content
"""
def load_default_config_inputs():
    
    logging.info(f"Loading default config inputs")
    
    default_filename = "default-config-inputs"
    p5 = os.path.join(__CWD__, default_filename + ".json")
    
    try: 
        with open(p5, "r") as f:
            config_inputs = json.load(f)
    except Exception as e:
        logging.error(f"Failed to open path: '{p5}'")
        raise Exception(e)
    
    return config_inputs

"""_summary_
"""
def validate_exceptions(exceptions):
    
    logging.info(f"Validating exceptions")
    
    for exception in exceptions:
        if not "name" in exception or exception["name"] == "":
            raise Exception("Error in exception. Invalid exception object - missing name")
        name = exception["name"]

        # validate system exception attribute found
        attributes = exception.get("attributes", {})
        if not attributes.get("systemException", False):
            raise Exception(f"Error in exception '{name}'. expected 'systemException' attribute: {exception}")
        if not "resources" in exception:
            raise Exception(f"Error in exception '{name}'. Invalid exception object - missing resources filed")
        if not "posturePolicies" in exception:
            raise Exception(f"Error in exception '{name}'. Invalid exception object - missing posturePolicies filed")


"""split the exceptions 
"""
def split_exceptions(exceptions):
    
    logging.info(f"Splitting exceptions")
    
    splitted_exceptions = []    
    base_name_to_index = dict()

    for exception in exceptions:
        if "resources" in exception and len(exception["resources"]) > 1:
            for i, resource in enumerate(exception["resources"]):
                tmp_exception = copy.deepcopy(exception)
                tmp_exception["resources"] = [resource]
                tmp_exception_base_name = tmp_exception['name']

                if tmp_exception_base_name in base_name_to_index:
                    base_name_to_index[tmp_exception_base_name] += 1 
                else:
                    base_name_to_index[tmp_exception_base_name] = 1
                
                tmp_exception["name"] = f"{tmp_exception_base_name}-{base_name_to_index[tmp_exception_base_name]}"
                splitted_exceptions.append(tmp_exception)
        else:
            splitted_exceptions.append(copy.deepcopy(exception))
            
    splitted_exceptions = remove_duplicate_exceptions(splitted_exceptions)
    return splitted_exceptions

"""removing duplications of exceptions
"""
def remove_duplicate_exceptions(exceptions: List) -> List:
    
    logging.info(f"Removing duplicate exceptions")
    
    no_duplicates = []
    checking_set = set() 

    for exception in exceptions:
        exception_copy = copy.deepcopy(exception)
        exception_copy['name'] = ""
        exception_json_str = json.dumps(exception_copy, sort_keys=True)
        if exception_json_str in checking_set:
            continue
        checking_set.add(exception_json_str)
        no_duplicates.append(exception)
    return no_duplicates

"""function loads all files under exceptiosn folder 
"""
def load_exceptions():
    
    exceptions = os.path.join(__CWD__, 'exceptions')
    logging.info(f"Loading exceptions from folder '{exceptions}'")
    
    exceptions_path = Path(exceptions).glob('**/*.json')
    loaded_exceptions = []

    for path in exceptions_path:
        if ignore_file(path.name):
            continue
        path_in_str = str(path)
        
        try:
            with open(path_in_str, "r") as f:
                exceptions = json.load(f)
        except Exception as e:
            logging.error(f"Failed to open control: '{path_in_str}'. With Error '{e}'")
            raise TypeError(e)
        
        if not isinstance(exceptions, list):
            logging.error(f"Exceptions file '{exceptions}' is not a list")
        loaded_exceptions.extend(exceptions)

    # We split the exceptions this way we wont have large exceptions objects
    splitted_exceptions = split_exceptions(loaded_exceptions)

    # Validate exceptions object
    validate_exceptions(splitted_exceptions)
    return splitted_exceptions

"""output JSON format
"""
def export_json(data: dict, f_name:str, output_path: str):
    
    logging.info(f"Creating JSON files for '{f_name}'")
    
    os.makedirs(output_path, exist_ok=True)
    try:    
        # generate with extentions for system testing 
        with open(os.path.join(output_path, f"{f_name.lower()}.json"), "w") as f:
            f.write(json.dumps(data, indent=4))
        # generate without extentions for backward compatability 
        # with open(os.path.join(output_path, f"{f_name.lower()}"), "w") as f:
        #     f.write(json.dumps(data, indent=4))
    except Exception as e:
        logging.error(f"failed to open path: '{output_path}'")
        raise TypeError(e)

"""output CSV format
"""
def create_cvs_file(header, rows, filename, output_path):
    
    logging.info(f"Creating CSV files for '{filename}'")

    try:
        os.makedirs(output_path, exist_ok=True)
        with open(os.path.join(output_path, f"{filename}.csv"), 'w', encoding='UTF8', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(header)
            writer.writerows(rows)
    except Exception as e:
        logging.error(f"failed to open path: '{output_path}'")
        raise TypeError(e)
    
"""main function
"""
if __name__ == '__main__':
    
    # init logger and config template
    logging.basicConfig(format='%(asctime)s | %(levelname)s | %(message)s', datefmt='%d-%m-%YT%H:%M:%S', level=logging.INFO)
    logging.info("export.py script started")
    
    output_dir_name = os.getenv("OUTPUT") if os.getenv("OUTPUT") else "release"   # creating local release dir. if parameter 'OUTPUT' exist creating pre-release
    loaded_rules, rules_list = load_rules()     # load all rules
    controls, controls_list = load_controls(loaded_rules)   # loading controls list
    validate_controls()   # validating controls scanned
    frameworks, frameworks_list = load_frameworks(loaded_controls=controls)  # load all frameworks
    default_config_inputs = load_default_config_inputs()  # load default config json file
    attack_tracks_list = load_attack_tracks()   # load attack tracks data
    exceptions_list = load_exceptions() # load exceptions from exceptions folder
    
    # create full framework json files
    # TODO - delete when kubescape works with csv files
    for k, v in frameworks.items():
        export_json(data=v, f_name=k, output_path=output_dir_name)
    
    # Generate json files: [frameworks, controls, rules]
    export_json(frameworks_list, 'frameworks', output_dir_name)
    export_json(controls_list, 'controls', output_dir_name)
    export_json(rules_list, 'rules', output_dir_name)
    export_json(default_config_inputs, 'default_config_inputs', output_dir_name)
    export_json(attack_tracks_list, 'attack-tracks', output_dir_name)
    export_json(exceptions_list, 'exceptions', output_dir_name)

    # generate CSV files: [frameworkName, ControlID, ControlName]
    header1 = ['ControlID', 'RuleName']
    header2 = ['frameworkName', 'ControlID', 'ControlName']
    create_cvs_file(header1, __CONTROL_RULE_ROWS__, 'ControlID_RuleName', output_dir_name)
    create_cvs_file(header2, __FRAMEWORK_CONTROL_ROWS__, 'FWName_CID_CName', output_dir_name)
    
    logging.info(f"Script ended successfully, quitting.")
