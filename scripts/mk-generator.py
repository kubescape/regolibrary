"""
This script is used to generate a markdown file for each control in the `controls` folder. 
The generated markdown files are placed into the `docs/controls` directory. 
Each markdown file contains detailed information about a control, 
such as its severity, description, related resources, test, remediation, and example. 
"""

import os
import json

def ignore_framework(framework_name: str):
    """
    determines whether or not to ignore a framework based on its name.

    Parameters
    ----------
    framework_name: the name of the framework

    Returns
    --------
    True if the framework should be ignored, False otherwise
    
    """
    return framework_name == 'YAML-scanning' or framework_name.startswith('developer')

def get_frameworks_for_control(control):
    """
    returns the frameworks a given control conforms to.

    Parameters
    ----------
    control: the control object

    Returns
    -------
    a list of framework names

    """
    r = []
    # Loop through all the json files in the 'frameworks' directory
    for frameworks_json_file_name in filter(lambda fn: fn.endswith('.json'),os.listdir('frameworks')):
        framework = json.load(open(os.path.join('frameworks',frameworks_json_file_name)))
        if ignore_framework(framework['name']):
            continue
    
        # Under the active controls the framework has, check if the given control is one of them
        if "activeControls" in framework:
            for activeControl in framework["activeControls"]:
                if control['controlID'].lower() == activeControl["controlID"].lower():
                    r.append(framework['name'])
    return r

def create_md_for_control(control):
    """
    generates a markdown file for a given control.

    Parameters
    ----------
    control: the control object
    
    Returns
    -------
    the markdown text/file

    """
    related_resources = set()
    control_config_input = {}
    host_sensor = False
    cloud_control = False

    # Loop through all the rules of the control
    for rule_obj in control['rules']:
        # If the rule has a 'match' field, add its resources to the related resources
        if 'match' in rule_obj:
            for match_obj in rule_obj['match']:
                if 'resources' in match_obj:
                    related_resources.update(set(match_obj['resources']))
        # If the rule has a 'controlConfigInputs' field, add its configuration to the control configuration input
        if 'controlConfigInputs' in rule_obj:
            for control_config in rule_obj['controlConfigInputs']:
                control_config_input[control_config['path']] = control_config
        # If the rule has a 'attributes' field and it contains 'hostSensorRule', set host_sensor to True
        if 'attributes' in rule_obj:
            if 'hostSensorRule' in rule_obj['attributes']:
                host_sensor = True
        # If the rule has a 'relevantCloudProviders' field and it is not empty, set cloud_control to True
        if 'relevantCloudProviders' in rule_obj:
            cloud_control = len(rule_obj['relevantCloudProviders']) > 0

    # Start creating the markdown text
    md_text = ''
    md_text += '# %s - %s\n' % (control['controlID'], control['name']) + '\n'
    
    if host_sensor:
        md_text += '## Prerequisites\n *Run Kubescape with host sensor (see [here](https://hub.armo.cloud/docs/host-sensor))*\n \n'
    if cloud_control:
        md_text += '## Prerequisites\n *Integrate with cloud provider (see [here](https://hub.armosec.io/docs/kubescape-integration-with-cloud-providers))*\n \n'
    frameworks = get_frameworks_for_control(control)
    md_text += '## Framework%s\n' % ('s' if len(frameworks) > 1 else '')
    md_text += '\n'.join(['* ' + framework for framework in frameworks]) + '\n \n'
    md_text += '## Severity\n'
    # severity map: https://github.com/kubescape/opa-utils/blob/master/reporthandling/apis/severity.go#L34
    severity_map = {1:'Low',2:'Low',3:'Low',4:'Medium',5:'Medium',6:'Medium',7:'High',8:'High',9:'Critical',10:'Critical'}
    md_text += '%s\n' % severity_map[int(control['baseScore'])] + '\n'
    if 'long_description' in control or 'description' in control:
        description = control['long_description'] if 'long_description' in control else control['description']
        if description.strip():
            md_text += '## Description of the issue\n'
    if len(control_config_input):
        description += ' Note, [this control is configurable](#configuration-parameters).'
    md_text += description + '\n \n'
    if related_resources:
        md_text += '## Related resources\n'
        md_text += ', '.join(sorted(list(related_resources))) + '\n \n'
        
    md_text += '## What this control tests \n'
    test = control['test'] if 'test' in control else control['description']
    md_text += test + '\n \n'

    if 'manual_test' in control and control['manual_test'].strip():
        md_text += '## How to check it manually \n'
        manual_test = control['manual_test'] 
        md_text += manual_test + '\n \n'

    if 'remediation' in control and control['remediation'].strip():
        md_text += '## Remediation\n'
        md_text += control['remediation'] + '\n \n'
    if 'impact_statement' in control and control['impact_statement'].strip() and control['impact_statement'] != 'None':
        md_text += '### Impact Statement\n' + control['impact_statement'] + '\n \n'
    if 'default_value' in control and control['default_value'].strip():
        md_text += '### Default Value\n' + control['default_value'] + '\n \n'

    if len(control_config_input):
        configuration_text = '## Configuration parameters \n You can adjust the configuration of this control to suit your specific environment. [Read the documentation on configuring controls](../frameworks-and-controls/configuring-controls.md) to learn more.\n \n'
        for control_config_name in control_config_input:
            control_config = control_config_input[control_config_name]
            # configuration_text += '### ' + control_config['name'] + '\n'
            config_name = control_config['path'].split('.')[-1]
            configuration_text += '* ' '[' + config_name + '](../frameworks-and-controls/configuring-controls.md#%s)'%config_name.lower() + ':' + '\n'
            configuration_text += control_config['description'] + '\n \n'
        md_text += configuration_text

    if 'example' in control and control['example'].strip():
        md_text += '## Example\n'
        md_text += '```\n' + control['example'] + '\n```' + '\n'
    return md_text

def generate_index_md(controls):
    """
    Generates the content for the index.md file based on the provided list of controls.

    Parameters
    ----------
    controls: A list of control objects.

    Returns
    ------- 
    str: The generated content for the index.md file.

    """
    # Sort the controls list based on control ID
    controls.sort(key=lambda control: convert_control_id_to_doc_order(control['controlID']))

    index_md = "# Control library\n\nEach control in the Kubescape control library is documented under this page.\n\n"
    index_md += "| Control | Name | Framework |\n"
    index_md += "| --- | --- | --- |\n"

    for control in controls:
        control_id = control['controlID']
        control_name = control['name']
        control_frameworks = get_frameworks_for_control(control)
        control_link = control_id.lower().replace(".", "-") + ".md"
        index_md += "| [%s](%s) | %s | %s |\n" % (control_id, control_link, control_name, ", ".join(control_frameworks))

    return index_md

def generate_slug(control):
    """
    Generates a slug for a given control.

    Parameters
    ----------
    control: The control object.

    Returns 
    -------
    str: The generated slug for the control.

    """
    return control['controlID'].lower().replace(".", "-")

def get_configuration_parameters_info():
    """
    Fetches and obtains the control's configuration parameters information.

    Returns
    -------
    tuple: A tuple containing two dictionaries - config_parameters and default_config_inputs.
        - config_parameters: A dictionary mapping configuration parameter names to their corresponding configuration objects.
        - default_config_inputs: A dictionary containing default configuration inputs.
    """
    default_config_inputs = None
    with open('default-config-inputs.json','r') as f:
        default_config_inputs = json.load(f)['settings']['postureControlInputs']

    config_parameters = {}
    for control_json_file_name in filter(lambda fn: fn.endswith('.json'),os.listdir('controls')):
        try:
            control_obj = json.load(open(os.path.join('controls',control_json_file_name)))
            control_obj['rules'] = []
            for rule_directory_name in os.listdir('rules'):
                rule_metadata_file_name = os.path.join('rules',rule_directory_name,'rule.metadata.json')
                if os.path.isfile(rule_metadata_file_name):
                    rule_obj = json.load(open(rule_metadata_file_name))
                    if rule_obj['name'] in control_obj['rulesNames']:
                        control_obj['rules'].append(rule_obj)  
                        if 'controlConfigInputs' in rule_obj:
                            for config in rule_obj['controlConfigInputs']:
                                name = config['path'].split('.')[-1]
                                config_parameters[name] = config
        except Exception as e:
            print('error processing %s: %s'%(control_json_file_name,e))
        
    return config_parameters, default_config_inputs

# Function to convert a control id to a doc order
def convert_control_id_to_doc_order(control_id: str) -> int:
    """get a control_id and returns it's expected order in docs.
    control_id is expected to either have "c-" or "cis-" prefix, otherwise raises an error.

    Parameters
    ----------
    control_id : str
        A string of structure "c-xxx" or "cis-x.y.z"
        
    Returns
    ---------
    int
    
    """
    control_id = control_id.lower()
    
    
    if "c-" in control_id:
        return int(control_id.replace("c-", ""))
    
    if "cis-" in control_id:
        return convert_dotted_section_to_int(control_id.replace("cis-", ""))

    raise Exception(f"control_id structure unknown {control_id}")

# Function to convert a dotted section to an int
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

# Function to find inactive controls in docs
def find_inactive_controls_in_docs(list_docs : list, list_active: list) -> list:
    """returns a list of controls that doesn't exist in rego but exit in docs.

    Parameters
    ----------
    list_docs : list
        a list of slugs in docs
        
    list_active: list
        a list of active controls from rego
        
        
    Returns
    ---------
    list - item that exist in list_docs but doesn't exist in list_active

    """
    return list(sorted(set(list_docs)- set(list_active)))

def main():
    # Define the directory where the Markdown files should be created.
    docs_dir = 'docs/controls'

    # Ensure the directory exists, if not create it
    if not os.path.exists(docs_dir):
        os.makedirs(docs_dir)

    # Fetches the Configuration parameters and related resources per control
    config_parameters, default_config_inputs = get_configuration_parameters_info()

    # Processing and obtaining the parameters for each control
    i = 0
    for config_parameters_path in sorted(list(config_parameters.keys())):
        print('Processing ',config_parameters_path)
        # Create md
        md = '# %s\n' % config_parameters_path
        md += '## Description\n'
        md += config_parameters[config_parameters_path]['description'] + '\n'
        md += '## Default values\n'
        for dvalue in default_config_inputs[config_parameters_path]:
            md += '* %s\n' % dvalue

        title = 'Parameter: %s' % config_parameters_path
        config_parameter_slug = 'configuration_parameter_' + config_parameters_path.lower()
        i = i + 1

    controls = []
    # Process controls.
    for control_json_file_name in filter(lambda fn: fn.endswith('.json'), os.listdir('controls')):
        print('processing %s' % control_json_file_name)
        control_obj = json.load(open(os.path.join('controls', control_json_file_name)))

        base_dir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
        if 'controlID' in control_obj:
            controlID = control_obj['controlID']
            example_file_name = controlID.replace('C-00','c0') + '.yaml'
            example_file_name = os.path.join('controls','examples',example_file_name)
            if os.path.isfile(example_file_name):
                with open(example_file_name) as f:
                    control_obj['example'] = f.read()
                   
        if 'example' in control_obj and len(control_obj['example']) > 0 and control_obj['example'][0] == '@':
            example_file_name = os.path.join(base_dir,control_obj['example'][1:])
            if os.path.isfile(example_file_name):
                with open(example_file_name) as f:
                    control_obj['example'] = f.read()
            else:
                print('warning: %s is not a file' % example_file_name)

        control_obj['rules'] = []
        for rule_directory_name in os.listdir('rules'):
            rule_metadata_file_name = os.path.join('rules',rule_directory_name,'rule.metadata.json')
            if os.path.isfile(rule_metadata_file_name):
                rule_obj = json.load(open(rule_metadata_file_name))
                if rule_obj['name'] in control_obj['rulesNames']:
                    control_obj['rules'].append(rule_obj)
                        
        controls.append(control_obj)

        # Generate a Markdown document for the control.
        md = create_md_for_control(control_obj)

        # Generate a slug for the control.
        slug = generate_slug(control_obj)

        # Define the path of the Markdown file.
        md_file_path = os.path.join(docs_dir, slug + '.md')

        # Write the Markdown document to the file.
        with open(md_file_path, 'w') as md_file:
            md_file.write(md)

        print('created or updated %s' % md_file_path)

    # Generate the index.md file
    index_md = generate_index_md(controls)

    # Define the path of the index.md file.
    index_md_file_path = os.path.join(docs_dir, "index.md")

    # Write the index.md file
    with open(index_md_file_path, 'w') as index_md_file:
        index_md_file.write(index_md)

    print('created or updated %s' % index_md_file_path)

# Run the main function if the script is run as a standalone program
if __name__ == '__main__':
    main()
