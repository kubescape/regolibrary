import requests
import os
import json
import re

class ReadmeApi(object):
    def __init__(self):
        super().__init__()
        self.doc_version = None

    def authenticate(self, api_key):
        r = requests.get('https://dash.readme.com/api/v1', auth=(api_key, ''))
        if r.status_code != 200:
            raise Exception('Failed to authenticate')
        auth_response = r.json()
        self.jwt = auth_response['jwtSecret']
        self.base_url = auth_response['baseUrl']
        self.api_key = api_key

    def set_version(self, version:str):
        self.doc_version = version

    def get_categories(self):
        url = "https://dash.readme.com/api/v1/categories"

        querystring = {"perPage":"1000","page":"1"}

        r = requests.request("GET", url, params=querystring, auth=(self.api_key, ''))

        if r.status_code != 200:
            raise Exception('Failed to get categories')

        return r.json()

    def get_category(self,category_slug : str):
        url = "https://dash.readme.com/api/v1/categories/%s" % category_slug

        r = requests.request("GET", url,headers={"Accept": "application/json"}, auth=(self.api_key, ''))

        if r.status_code != 200:
            raise Exception('Failed to get categories')

        return r.json()

    def get_docs_in_category(self, category_slug: str):
        url = "https://dash.readme.com/api/v1/categories/%s/docs" % category_slug

        r = requests.request("GET", url, headers={"Accept":"application/json"}, auth=(self.api_key, ''))

        if r.status_code != 200:
            raise Exception('Failed to docs for category')

        return r.json()

    def get_doc(self, doc_slug: str):
        url = "https://dash.readme.com/api/v1/docs/%s" % doc_slug

        r = requests.request("GET", url, headers={"Accept":"application/json"}, auth=(self.api_key, ''))

        if r.status_code == 404:
            return None
        if r.status_code < 200 or 299 < r.status_code:
            raise Exception(f'Failed to docs for category, status_code: {r.status_code}, url: {url}')

        return r.json()

    def delete_doc(self, doc_slug: str):
        url = "https://dash.readme.com/api/v1/docs/%s" % doc_slug

        r = requests.request("DELETE", url, headers={"Accept":"application/json"}, auth=(self.api_key, ''))

        if r.status_code < 200 or 299 < r.status_code:
            raise Exception('Failed to delete doc (%d)'%r.status_code)
    
    def create_doc(self, slug: str, parent_id: str, order: any, title: str, body: str, category: str):
        url = "https://dash.readme.com/api/v1/docs"

        payload = {
            "hidden": False,
            "order": order,
            "title": title,
            "type": "basic",
            "body": body,
            "category": category,
            "parentDoc": parent_id,
            "slug": slug
        }
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        r = requests.request("POST", url, json=payload, headers=headers, auth=(self.api_key, ''))


        if r.status_code < 200 or 299 < r.status_code:
            raise Exception('Failed to create doc: %s'%r.text)

        return r.json()
        
    def update_doc(self, doc_slug: str, order: any, title: str, body: str, category: str):

        url = "https://dash.readme.com/api/v1/docs/%s" % doc_slug

        payload = {
            "hidden": False,
            "order": order,
            "title": title,
            "body": body,
            "category": category
        }
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        r = requests.request("PUT", url, json=payload, headers=headers, auth=(self.api_key, ''))

        if r.status_code < 200 or 299 < r.status_code:
            raise Exception('Failed to update doc: %s'%r.text)

        return r.json()

def validate_readme_structure(readmeapi : ReadmeApi):
    categories = readmeapi.get_categories()
    filtered_categories = list(filter(lambda c: c['title'] == 'Controls',categories))
    if len(filtered_categories) != 1:
        raise Exception('Readme structure validation failure: missing "Controls" category (or more than one)')
    controls_category = filtered_categories[0]
    docs_in_control_category = readmeapi.get_docs_in_category(controls_category['slug'])
    filtered_docs = list(filter(lambda d: d['title'] == 'Controls',docs_in_control_category))
    if len(filtered_docs) != 1:
        raise Exception('Readme structure validation failure: missing "Controls" document')

def get_document_for_control(readmeapi : ReadmeApi, control):
    categories = readmeapi.get_categories()
    filtered_categories = list(filter(lambda c: c['title'] == 'Controls',categories))
    if len(filtered_categories) != 1:
        raise Exception('Readme structure failure: missing "Controls" category (or more than one)')
    controls_category = filtered_categories[0]
    docs_in_control_category = readmeapi.get_docs_in_category(controls_category['slug'])
    filtered_docs = list(filter(lambda d: d['title'].startswith(control['id']),docs_in_control_category))
    if len(filtered_docs) != 1:
        return None
    control_doc = filtered_docs[0]
    return control_doc

def ignore_framework(framework_name: str):
    return framework_name == 'YAML-scanning' or framework_name.startswith('developer')

def get_frameworks_for_control(control):
    r = []
    for frameworks_json_file_name in filter(lambda fn: fn.endswith('.json'),os.listdir('frameworks')):
        framework = json.load(open(os.path.join('frameworks',frameworks_json_file_name)))
        if ignore_framework(framework['name']):
            continue
    
        if "activeControls" in framework:
            for activeControl in framework["activeControls"]:
                if control['controlID'].lower() == activeControl["controlID"].lower():
                    r.append(framework['name'])
    return r
   

def create_md_for_control(control):
    related_resources = set()
    control_config_input = {}
    host_sensor = False
    cloud_control = False
    for rule_obj in control['rules']:
        if 'match' in rule_obj:
            for match_obj in rule_obj['match']:
                if 'resources' in match_obj:
                    related_resources.update(set(match_obj['resources']))
        if 'controlConfigInputs' in rule_obj:
            for control_config in rule_obj['controlConfigInputs']:
                control_config_input[control_config['path']] = control_config
        if 'attributes' in rule_obj:
            if 'hostSensorRule' in rule_obj['attributes']:
                host_sensor = True
        if 'relevantCloudProviders' in rule_obj:
            cloud_control = len(rule_obj['relevantCloudProviders']) > 0

    md_text = ''
    if host_sensor:
        md_text += '## Prerequisites\n*Run Kubescape with host sensor (see [here](https://hub.armo.cloud/docs/host-sensor))*\n'
    if cloud_control:
        md_text += '## Prerequisites\n*Integrate with cloud provider (see [here](https://hub.armosec.io/docs/kubescape-integration-with-cloud-providers))*\n'
    md_text += '## Framework\n'
    md_text += ', '.join(get_frameworks_for_control(control)) + '\n'
    md_text += '## Severity\n'
    # severity map: https://github.com/kubescape/opa-utils/blob/master/reporthandling/apis/severity.go#L34
    severity_map = {1:'Low',2:'Low',3:'Low',4:'Medium',5:'Medium',6:'Medium',7:'High',8:'High',9:'Critical',10:'Critical'}
    md_text += '%s\n' % severity_map[int(control['baseScore'])]
    md_text += '## Description of the the issue\n'
    description = control['long_description'] if 'long_description' in control else control['description']
    if len(control_config_input):
        description += 'Note, this control is configurable. See below the details.'
    md_text += description + '\n'
    md_text += '## Related resources\n'

    md_text += ', '.join(sorted(list(related_resources))) + '\n'
    md_text += '## What does this control test\n'
    test = control['test'] if 'test' in control else control['description']
    md_text += test + '\n'

    if 'manual_test' in control:
        md_text += '## How to check it manually\n'
        manual_test = control['manual_test'] 
        md_text += manual_test + '\n'

    md_text += '## Remediation\n'
    md_text += control['remediation'] + '\n'
    if 'impact_statement' in control:
        md_text += '### Impact Statement\n' + control['impact_statement'] + '\n'
    if 'default_value' in control:
        md_text += '### Default Value\n' + control['default_value'] + '\n'

    if len(control_config_input):
        configuration_text = '## Configuration\nThis control can be configured using the following parameters. Read CLI/UI documentation about how to change parameters.\n'
        for control_config_name in control_config_input:
            control_config = control_config_input[control_config_name]
            configuration_text += '### ' + control_config['name'] + '\n'
            config_name = control_config['path'].split('.')[-1]
            configuration_text += '[' + config_name + '](doc:configuration_parameter_%s)'%config_name.lower() + '\n'
            configuration_text += control_config['description'] + '\n'
        md_text += configuration_text

    md_text += '## Example\n'
    if 'example' in control:
        md_text += '```\n' +control['example'] + '\n```' + '\n'
    else:
        md_text += 'No example\n'
    return md_text

def generate_slug(control):
    return control['controlID'].lower().replace(".", "-")

def get_configuration_parameters_info():
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

def main():
    API_KEY = os.getenv('README_API_KEY')
    if not API_KEY:
        raise Exception('README_API_KEY is not defined')
    
    # Validate connection
    readmeapi = ReadmeApi()
    readmeapi.authenticate(API_KEY)
    print('Authenticated')

    # Validated structure
    validate_readme_structure(readmeapi)
    print('Readme structure validated')

    control_category_obj = readmeapi.get_category('controls')
    parent_control_doc = readmeapi.get_doc('controls')
    if os.getenv('PRUNE_CONTROLS'):
        for control_doc in readmeapi.get_docs_in_category('controls'):
            if control_doc['_id'] == parent_control_doc['_id']:
                for child_doc in control_doc['children']:
                    readmeapi.delete_doc(child_doc['slug'])
                    print('Deleted %s'%child_doc['slug'])

    # Configuration parameter processing
    config_parameters, default_config_inputs = get_configuration_parameters_info()
    # parent_configuration_parameters_doc = readmeapi.get_doc('configuration-parameters')
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
        config_parameter_doc = readmeapi.get_doc(config_parameter_slug)

        if config_parameter_doc:
            readmeapi.update_doc(config_parameter_slug,i,title,md,control_category_obj['_id'])
            print('\tupdated')
        else:
            parent_config_param_doc = readmeapi.get_doc('configuration-parameters')
            readmeapi.create_doc(config_parameter_slug,parent_config_param_doc['_id'],i,title,md,control_category_obj['_id'])
            print('\tcreated')
        i = i + 1
    
    # Start processing
    active_controls_slugs = []
    for control_json_file_name in filter(lambda fn: fn.endswith('.json'),os.listdir('controls')):
        if True:
            print('processing %s' % control_json_file_name)
            control_obj = json.load(open(os.path.join('controls',control_json_file_name)))

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

            md = create_md_for_control(control_obj)
            
            title = '%(controlID)s - %(name)s' % control_obj

            control_slug = generate_slug(control_obj)
            
            control_doc = readmeapi.get_doc(control_slug)
            
            control_id = control_obj["controlID"]

            try:
                order = convert_control_id_to_doc_order(control_id)
            except Exception as e:
                 print(f"Error: couldn't generate order for control id {control_id} because {e}")
                 continue

            if control_doc and len(control_obj['controlID']) > 2:
                readmeapi.update_doc(control_slug,order,title,md,control_category_obj['_id'])
                print("update:", control_slug)
                print(f'\tupdated control_slug {control_slug}')
            else:
                readmeapi.create_doc(control_slug,parent_control_doc['_id'],order,title,md,control_category_obj['_id'])
                print(f'\tcreated control_slug {control_slug}')
            
            active_controls_slugs.append(control_slug)

    # delete inactive controls from docs
    docs_slugs = get_controls_doc_slugs(readmeapi)
    inactive_slugs = find_inactive_controls_in_docs(docs_slugs, active_controls_slugs)
    
    for slug in inactive_slugs:
        try:
            readmeapi.delete_doc(slug)
        except Exception as e:
            print(f"\tFailed to delete control_slug {slug} because {e}")
            continue
        print(f"\tDeleted control_slug {slug}")
    
    exit(0)




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
               
def get_controls_doc_slugs(readmeapi: ReadmeApi) -> list:
    """returns a list of slugs exist under the "controls" category

    Parameters
    ----------
    readmeapi : ReadmeApi
        ReadmeApi object
        
    Returns
    ---------
    list - active slugs under "controls" category

    """
    parent_control_doc = readmeapi.get_doc('controls')
    docs = readmeapi.get_docs_in_category("controls")

    controls_docs = [control_doc for control_doc in docs if control_doc["_id"] == parent_control_doc['_id']][0]
    child_docs = [child_doc["slug"] for child_doc in controls_docs["children"]]
     
    return child_docs

if __name__ == '__main__':
    main()

