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
            raise Exception('Failed to docs for category')

        return r.json()

    def delete_doc(self, doc_slug: str):
        url = "https://dash.readme.com/api/v1/docs/%s" % doc_slug

        r = requests.request("DELETE", url, headers={"Accept":"application/json"}, auth=(self.api_key, ''))

        if r.status_code < 200 or 299 < r.status_code:
            raise Exception('Failed to delete doc (%d)'%r.status_code)
    
    def create_doc(self, slug: str, parent_id: str, order: int, title: str, body: str, category: str):
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
        
    def update_doc(self, doc_slug: str, order: int, title: str, body: str, category: str):

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



def get_frameworks_for_control(control):
    r = []
    for frameworks_json_file_name in filter(lambda fn: fn.endswith('.json'),os.listdir('frameworks')):
        framework = json.load(open(os.path.join('frameworks',frameworks_json_file_name)))
        if framework['name'].startswith('developer'):
            continue
        if control['name'] in framework['controlsNames']:
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
    md_text += '# %s\n' % control['name']
    if host_sensor:
        md_text += '*Note: to enable this control run Kubescape with host sensor (see [here](https://hub.armo.cloud/docs/host-sensor))*\n'
    if cloud_control:
        md_text += '*Note: this control relevant for cloud managed Kubernetes cluster*\n'
    md_text += '## Framework\n'
    md_text += ', '.join(get_frameworks_for_control(control)) + '\n'
    md_text += '## Severity\n'
    severity_map = {'1':'Low','2':'Low','3':'Low','4':'Low','5':'Medium','6':'Medium','7':'High','8':'High','9':'Critical','10':'Critical'}
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
    md_text += '## Remediation\n'
    md_text += control['remediation'] + '\n'

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
    return control['id'].lower()

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
    #print("Parent doc\n",parent_control_doc)
    if os.getenv('PRUNE_CONTROLS'):
        for control_doc in readmeapi.get_docs_in_category('controls'):
            if control_doc['_id'] == parent_control_doc['_id']:
                for child_doc in control_doc['children']:
                    readmeapi.delete_doc(child_doc['slug'])
                    print('Deleted %s'%child_doc['slug'])

    # Configuration parameter processing
    config_parameters, default_config_inputs = get_configuration_parameters_info()
    parent_configuration_parameters_doc = readmeapi.get_doc('configuration-parameters')
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
    for control_json_file_name in filter(lambda fn: fn.endswith('.json'),os.listdir('controls')):
        #try:
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
            
            title = '%(id)s - %(name)s' % control_obj

            control_slug = generate_slug(control_obj)
            
            control_doc = readmeapi.get_doc(control_slug)

            if control_doc and len(control_obj['id']) > 2:
                readmeapi.update_doc(control_slug,int(control_obj['id'][2:]),title,md,control_category_obj['_id'])
                print('\tupdated')
            else:
                readmeapi.create_doc(control_slug,parent_control_doc['_id'],int(control_obj['id'][2:]),title,md,control_category_obj['_id'])
                print('\tcreated')

        #except Exception as e:
        #    print('error processing %s: %s'%(control_json_file_name,e))

    # Delete children of control doc in co
    exit(0)


if __name__ == '__main__':
    main()

