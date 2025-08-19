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
import logging
import sys


# constants
currDir = os.path.abspath(os.getcwd())
frameworks_dir = os.path.join(currDir, 'frameworks')
framework_name_to_filename_mapping = {}
logging.basicConfig(level=logging.INFO)


# ================================================


def init_framework_name_to_filename_mapping():
    for filename in os.listdir(frameworks_dir):
        logging.info(f"Checking file: {filename}")
        # Load the JSON files
        if filename.endswith('.json'):
            logging.info(f"file {filename} detected as a JSON")
            try:
                with open(os.path.join(frameworks_dir, filename)) as f1:
                    framework = json.load(f1)
                    framework_name_to_filename_mapping[framework['name']] = filename
            except Exception as e:
                logging.error(f"Error detected with file {filename}. Error: {e}")
                sys.exit(1)



def init_parser():
    # Set up the argument parser
    logging.info(f"Initializing parser")
    parser = argparse.ArgumentParser()
    parser.add_argument("--framework", "-fw", required=True, help="Name of the framework to add the control to")
    parser.add_argument("--firstCleanList", "-clean", required=False, help="Clean controlIds list before population")
    # Parse the command line arguments
    args = parser.parse_args()
    return args


def restart_controlIDs_list(framework):
    logging.info(f"Restarting controls ID list")
    for subsection1 in framework["subSections"]:
        if "subSections" in framework["subSections"][subsection1]:
            for item in framework["subSections"][subsection1]["subSections"]:
                framework["subSections"][subsection1]["subSections"][item]["controlsIDs"] = []
    logging.info(f"Restarting controls ID completed")


def populate_controlIds_list(framework):
    logging.info(f"Populating controls ID list")
    for active_control in framework["activeControls"]:
        control_id = active_control["controlID"]
        cis_subsection = active_control["patch"]["name"].split(" ")[0].replace("CIS-", "")
        sections = cis_subsection.split(".")
        if "subSections" in framework["subSections"][sections[0]]:
            tmp_controlIDs = framework["subSections"][sections[0]]["subSections"][sections[1]]["controlsIDs"]
            if control_id not in tmp_controlIDs:
                tmp_controlIDs.append(control_id)


def main(framework):
    # args = init_parser()
    # framework_name = args.framework
    framework_name = framework
    # restart_controlIDs_lists = args.firstCleanList
    restart_controlIDs_lists = True        

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
    logging.info("Script started")
    frameworks = ["cis-aks-t1.2.0", "cis-v1.10.0", "cis-eks-t1.7.0", "cis-eks-t1.7.0"]
    for i in frameworks:
        logging.info(f"Running on framework {i}")
        main(i)
    logging.info("Script ended")
    sys.exit(0)