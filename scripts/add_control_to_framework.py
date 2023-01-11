# Description: 
# This script adds a new control to a framework according to the new format - i.e to the activeControls field of the framework
# 

# To use: 
# Run from main directory:
# python3 scripts/add_control_to_framework.py -c <path to new control json> -b <controlID of the base control> -fw <Name of the framework to add the control to>
# for e.g: python3 scripts/add_control_to_framework.py -c path/to/control/CIS-4.1.1.json -b CIS-5.1.1 -fw CIS-EKS

# If no baseControlID is specified:
#   It will assume the control is new and generate a new controlID.
#   The script will also create a new file for the control in the controls directory, with the filename format controlID-name.json,
# If the baseControl already exists:
#   it will add the patch with fields that need to be overridden by new control.
# In both cases, the control will be added to the framework under the activeControls field in the following format:
# { 
#   "controlID": "C-NNNN",
#       "patch": {
#       "name": "control-name", (in cis frameworks: "CIS-NN.NN.NN-control-name")
#       ** other fields that need to be overridden by the new control **
#       }
# }
    
# Notice - currently all fields can be overridden apart from those in the list 'fields_not_to_compare'.
# To restrict other fields that can be overridden, add them to 'fields_not_to_compare'

# ================================================
import argparse
import json
import os
import re

# constants
currDir = os.path.abspath(os.getcwd())
controls_dir = os.path.join(currDir, 'controls')
frameworks_dir = os.path.join(currDir, 'frameworks')

controlID_to_filename_mapping = {}
framework_name_to_filename_mapping = {}
fields_not_to_compare = ['controlID', 'id', 'name', 'rulesNames', 'baseScore', 'attributes', 'control-CIS-ID']

# ================================================

# create mapping of old-cis control names to control filenames
def init_controlID_to_filename_mapping():
    for filename in os.listdir(controls_dir):
        # Load the JSON files
        if filename.endswith('.json'):
            with open(os.path.join(controls_dir, filename)) as f1:
                control = json.load(f1)
                controlID_to_filename_mapping[control['controlID']] = filename


def init_framework_name_to_filename_mapping():
    for filename in os.listdir(frameworks_dir):
        # Load the JSON files
        if filename.endswith('.json'):
            with open(os.path.join(frameworks_dir, filename)) as f1:
                framework = json.load(f1)
                framework_name_to_filename_mapping[framework['name']] = filename


def init_parser():
    # Set up the argument parser
    parser = argparse.ArgumentParser()
    parser.add_argument("--newControl", "-c", required=True, help="path to the new control json")
    parser.add_argument("--baseControlID", "-b", required=False, default=None, help="controlID of the base control")
    parser.add_argument("--framework", "-fw", required=True, help="Name of the framework to add the control to")

    # Parse the command line arguments
    args = parser.parse_args()
    return args

def get_numberID(controlID):
    if controlID.startswith("CIS"):
        return 0
    elif controlID.startswith("C"):
        return int(controlID[2:])
    else:
        raise Exception("Invalid controlID: " + controlID)

def generate_new_controlID():
    # Get current highest id from all controls
    highest_id = 0
    for controlID in controlID_to_filename_mapping:
        number = get_numberID(controlID)
        if number > highest_id:
            highest_id = number
    new_id = highest_id + 1
    # Format the new ID as "C-NNNN"
    formatted_id = f"C-{new_id:04d}"
    return formatted_id

def verify_control_not_in_framework(control_to_add, framework):
    for control in framework["activeControls"]:
        if control["controlID"] == control_to_add["controlID"]:
            raise Exception("Control: " + control_to_add["controlID"] + " already exists in framework: " + framework["name"])
        if control["patch"]["name"] == control_to_add["patch"]["name"]:
            raise Exception("Control with name: " + control_to_add["patch"]["name"] + " already exists in framework: " + framework["name"])

def save_control_in_new_file(new_control, controlID_to_add):
    # add file to controls directory, filename format is controlID-name.json, 
    # where name is all lowercase with no whitespace or special characters
    if "control-CIS-ID" in new_control:
        del new_control["control-CIS-ID"]
    name = new_control["name"].lower()
    name = re.sub(r'[^\w]', '', name)
    filename = controlID_to_add + "-" + name + ".json"
    with open(os.path.join(controls_dir, filename), "w") as output_file:
        json.dump(new_control, output_file, indent=4)
    print("saved new control to file: " + filename)

def main():
    args = init_parser()
    init_controlID_to_filename_mapping()
    init_framework_name_to_filename_mapping()
    
    controlID_to_add = None
    patch = {}
    
    # Load the new control json
    with open(args.newControl, "r") as input_file_1:
        new_control = json.loads(input_file_1.read())

    # Add name to patch
    # If control is added to a CIS framework, add the controlID to the name
    # else just add the name
    if "cis" in args.framework.lower():
        name = new_control["control-CIS-ID"] + " " + new_control["name"]
    else:
        name = new_control["name"]
    patch["name"] = name
    
    save_new_file = False
    # If the baseControlID is not specified, assume this is a new baseControl and use the new control ID
    if args.baseControlID is None:
        # if control has a CIS ID, generate a new internal ID
        if new_control["controlID"].startswith("CIS"):
            controlID_to_add = generate_new_controlID()
            new_control["controlID"] = controlID_to_add
            print("generated new ID for control: " + controlID_to_add)
        else:
            controlID_to_add = new_control["controlID"]
        if controlID_to_add not in controlID_to_filename_mapping:
            save_new_file = True
    # If the baseControlID is specified, compare the new control with it and generate a patch
    else:
        controlID_to_add = args.baseControlID
        if controlID_to_filename_mapping[controlID_to_add] is not None:
            filename = controlID_to_filename_mapping[controlID_to_add]
            with open(os.path.join(controls_dir, filename), "r") as input_file_2:
                baseControl = json.loads(input_file_2.read())
                # create patch with fields that need to be overridden in the framework for the new control
                for key, value in new_control.items():
                    if key not in fields_not_to_compare:
                        if value != baseControl[key]:
                            patch[key] = new_control[key]
        else:
            raise Exception("Base controlID not found")
          
    # create control object to add to the framework
    control_to_add = {
        "controlID": controlID_to_add,
    }
    if patch:
        control_to_add["patch"] = patch
    # print(controlID_to_add)
    
    # Load the framework json and add new control to activeControls
    filename = framework_name_to_filename_mapping[args.framework]
    with open(os.path.join(frameworks_dir, filename), "r+") as input_file_3:
        framework = json.load(input_file_3)
        if framework["activeControls"] is None:
            framework["activeControls"] = []
        # verify new control is not already in the framework
        verify_control_not_in_framework(control_to_add, framework)
        if save_new_file:
            save_control_in_new_file(new_control, controlID_to_add)
        framework["activeControls"].append(control_to_add)
        # Move the file pointer to the beginning of the file
        input_file_3.seek(0)
        json.dump(framework, input_file_3, indent=4)
    print("added control: " + controlID_to_add + " to framework: " + args.framework)

if __name__ == "__main__":
    main()