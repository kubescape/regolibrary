# Description: 
# This script adds a new control to a framework according to the new format - i.e to the activeControls field of the framework

# To use: python3 add_control_to_framework.py -c <path to new control json> -b <controlID of the base control> -fw <Name of the framework to add the control to>
# for e.g: python3 add_control_to_framework.py -c path/to/control/CIS-4.1.1.json -b CIS-5.1.1 -fw CIS-EKS

# If no baseControlID is specified, it will assume the control is new and add only add the controlID to the framework
# If the baseControl already exists, it will also add the patch with all new control fields that need to be overridden.
# notice - currently all fields can be overridden except for controlID and id.
# To restrict the fields that can be overridden, add them to the fields_not_to_compare list

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
fields_not_to_compare = ['controlID','id', 'rulesNames', 'baseScore']

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
        name = new_control["controlID"] + " " + new_control["name"]
    else:
        name = new_control["name"]
    patch["name"] = name
     
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
            # add file to controls directory, filename format is controlID-name.json, 
            # where name is all lowercase with no whitespace or special characters
            name = new_control["name"].lower()
            name = re.sub(r'[^\w]', '', name)
            filename = controlID_to_add + "-" + name + ".json"
            with open(os.path.join(controls_dir, filename), "w") as output_file:
                json.dump(new_control, output_file, indent=4)
            print("saved new control to file: " + filename)
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
        for control in framework["activeControls"]:
            if control["controlID"] == controlID_to_add:
                raise Exception("Control: " + controlID_to_add + " already exists in framework: " + args.framework)
        framework["activeControls"].append(control_to_add)
        # Move the file pointer to the beginning of the file
        input_file_3.seek(0)
        json.dump(framework, input_file_3, indent=4)
    print("added control: " + controlID_to_add + " to framework: " + args.framework)

if __name__ == "__main__":
    main()