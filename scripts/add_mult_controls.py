'''
This script is used to add multiple controls to a framework by running the add_control_to_framework.py script multiple times.
to run:
1. Update the file_path variable to the path to the directory containing the controls
2. Update the filename_to_id map to contain the filename to id mapping
3. Update the fw_path variable to the path to the framework
4. Run the script: python3 scripts/add_mult_controls.py
'''

import os
import subprocess

# Path to the file
file_path = "/home/yiscah/armo-projects/regolibrary/cis-aks-controls/"

# Map of filename to id of base control
filename_to_base_id = {
    "CIS-4.1.1.json": "C-0185",
    "CIS-4.1.2.json": "C-0186",
    "CIS-4.1.3.json": "C-0187"
}

# Path to the framework
fw_path = "cis-aks-t1.2.0"

# Loop over the filename to id map and run the command for each pair
for filename, control_id in filename_to_base_id.items():
    full_path = os.path.join(file_path, filename)
    cmd = ["python3", "scripts/add_control_to_framework.py", "-c", full_path, "-b", control_id, "-fw", fw_path]
    subprocess.run(cmd, check=True)
