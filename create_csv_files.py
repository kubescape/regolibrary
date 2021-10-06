import csv
import os
import json
from pathlib import Path

currDir = os.path.abspath(os.getcwd())
p1 = currDir + '/frameworks'
p2 = currDir + '/controls'
p3 = currDir + '/rules'

regofile = 'raw.rego'
frameworks_pathlist = Path(p1).glob('**/*.json')
controls_pathlist = Path(p2).glob('**/*.json')
rules_pathlist = Path(p3).glob('**/*.json')

control_dict = {}

def create_cvs_file(header, rows, filename):
    with open(filename, 'w', encoding='UTF8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)

def FWName_CID_CName():
    header = ['frameworkName', 'ControlID', 'ControlName']
    rows = []
  
    for path in frameworks_pathlist:
        path_in_str = str(path)
        curr_fw_json = None
        with open(path_in_str, "r") as f:
            curr_fw_json = json.load(f)
        for control_name in curr_fw_json['controlsNames']:
            rows.append([curr_fw_json['name'], control_dict[control_name], control_name])
    return header, rows

def ControlID_RuleName():
    header = ['ControlID', 'RuleName']
    rows = []
    for path in controls_pathlist:
        path_in_str = str(path)
        curr_control_json = None
        with open(path_in_str, "r") as f:
            curr_control_json = json.load(f)
        # create controlID-controlName map
        control_dict[curr_control_json['name']] = curr_control_json['id'] # TODO : change to 'controlID'
        for rule in curr_control_json['rulesNames']:
            rows.append([curr_control_json['id'], rule]) # TODO : change to 'controlID'
    return header, rows


# file 1 - 'ControlID', 'RuleName'
header, rows = ControlID_RuleName()
create_cvs_file(header, rows, 'ControlID_RuleName.csv')

# file 2 - frameworkName, ControlID, ControlName
header, rows = FWName_CID_CName()
create_cvs_file(header, rows, 'FWName_CID_CName.csv')

