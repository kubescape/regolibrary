######
# Description: Script populates ControlIDs list in CIS framework subsections.
# Params:
# -fw - the name of the framwork
# -clean - if true, first clean the controlIDs lists. False or not sent - add controlIds that doesn't exist on list
# ================================================

import argparse
import json
import os
import re

# constants
__CWD__ = os.path.abspath(os.getcwd())
__FRAMEWORKS_DIR__ = os.path.join(__CWD__, 'frameworks')
__FRAMEWORK_NAME_TO_FILENAME_MAPPING__ = {}

# ================================================


def init_framework_name_to_filename_mapping():
    file_list = os.listdir(__FRAMEWORKS_DIR__)
    for filename in file_list:
        # Load the JSON files
        if filename.endswith('.json'):
            try:
                with open(os.path.join(__FRAMEWORKS_DIR__, filename)) as f1:
                    framework = json.load(f1)
                    __FRAMEWORK_NAME_TO_FILENAME_MAPPING__[framework['name']] = filename
            except Exception as e:
                return TypeError(e)

def init_parser():
    # Set up the argument parser
    parser = argparse.ArgumentParser()
    parser.add_argument("--framework", "-fw", required=True, help="Name of the framework to add the control to")
    parser.add_argument("--firstCleanList", "-clean", required=False, help="Clean controlIds list before population")
    # Parse the command line arguments
    args = parser.parse_args()
    return args


def restart_controlIDs_list(framework):
    for subsection1 in framework["subSections"]:
        if "subSections" in framework["subSections"][subsection1]:
            for item in framework["subSections"][subsection1]["subSections"]:
                framework["subSections"][subsection1]["subSections"][item]["controlsIDs"] = []
        else:
            print(f"Cannot detect 'subSections' in framework {subsection1}")
            continue

def populate_controlIds_list(framework):
    for active_control in framework["activeControls"]:
        control_id = active_control["controlID"]
        cis_subsection = active_control["patch"]["name"].split(" ")[0].replace("CIS-", "")
        sections = cis_subsection.split(".")
        if "subSections" in framework["subSections"][sections[0]]:
            tmp_controlIDs = framework["subSections"][sections[0]]["subSections"][sections[1]]["controlsIDs"]
            if control_id not in tmp_controlIDs:
                tmp_controlIDs.append(control_id)
        else:
            print(f"Cannot detect 'subSections' in control {active_control}")
            continue



def main():
    args = init_parser()
    framework_name = args.framework
    restart_controlIDs_lists = args.firstCleanList

    init_framework_name_to_filename_mapping()
    
    # check if framwork name from passed arguments exist at the current folder
    if framework_name in __FRAMEWORK_NAME_TO_FILENAME_MAPPING__:

        framework_file_path = os.path.join(__FRAMEWORKS_DIR__, __FRAMEWORK_NAME_TO_FILENAME_MAPPING__[framework_name])

        #read framework json
        with open(framework_file_path) as f:
            framework = json.load(f)

        #clean controlIds list if required
        if restart_controlIDs_lists:
            restart_controlIDs_list(framework)

        #populate controlIDs list
        populate_controlIds_list(framework)


        # save framework
        with open(framework_file_path, "w") as outfile:
            outfile.write(json.dumps(framework, indent=4))
    else:
        print(f"Cannot find framework {framework_name}")
        pass

if __name__ == "__main__":
    # TODO: add comments and python convetion for all document
    main()