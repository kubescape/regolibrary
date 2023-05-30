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
currDir = os.path.abspath(os.getcwd())
frameworks_dir = os.path.join(currDir, 'frameworks')
framework_name_to_filename_mapping = {}

# ================================================


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


def populate_controlIds_list(framework):
    for active_control in framework["activeControls"]:
        control_id = active_control["controlID"]
        cis_subsection = active_control["patch"]["name"].split(" ")[0].replace("CIS-", "")
        sections = cis_subsection.split(".")
        if "subSections" in framework["subSections"][sections[0]]:
            tmp_controlIDs = framework["subSections"][sections[0]]["subSections"][sections[1]]["controlsIDs"]
            if control_id not in tmp_controlIDs:
                tmp_controlIDs.append(control_id)


def main():
    args = init_parser()
    framework_name = args.framework
    restart_controlIDs_lists = args.firstCleanList
        

    init_framework_name_to_filename_mapping()

    framework_file_path = os.path.join(frameworks_dir, framework_name_to_filename_mapping[framework_name])


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


if __name__ == "__main__":
    # TODO: add comments and python convetion for all document
    main()