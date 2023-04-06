#!/usr/bin/env python3
# Description:
# init-rule.py helps you bootstrapping a new rule from scratch.
# It scaffold and generate code in order to create rules fast.
#
# To use:
# Run the script from the regolibrary base directory in this way:
# python3 scripts/init-rule.py --name "name-of-new-rule"
# To get help:
# python3 scripts/init-rule.py --help

import argparse
import re
from os import path
import os
import sys

program_name = 'init-rule.py'
regex = "((([a-zA-Z0-9]+)\-)+([a-zA-Z0-9]+))"
rules_base_path = 'rules'
test_list_default = 'success,failed'
msga = """{{
    	"alertMessage": "{alert_message}",
    	"packagename": "armo_builtins",
    	"alertScore": {alert_score},
    	"failedPaths": ["{failed_paths}"],
    	"fixPaths":[{fix_paths}],
        "fixCommand": "{fix_command}",
    	"alertObject": {{
            {alert_object}
        }}
    }}
"""

raw_rego = """
package armo_builtins

deny[msga] {{

	msga := {}
}}
"""

set_k8s_api_objects = """"{}": [object]"""

set_external_objects = """"{}": object"""

set_use_from_kubescape_version = """
      "useFromKubescapeVersion": "{use_from_kubescape_version}","""

set_use_until_kubescape_version = """
      "useUntilKubescapeVersion": "{use_until_kubescape_version}","""

rule_metadata = """{{
    "name": "{rule_name}",
    "attributes": {{
      "armoBuiltin": true,{use_from_kubescape_version}{use_until_kubescape_version}
      "hostSensorRule": "{host_sensor_rule}",
      "imageScanRelated": {image_scan_related}
    }},
    "ruleLanguage": "Rego",
    "{match_type}": [
        {{
          "apiGroups": [],
          "apiVersions": [],
          "resources": []
        }}
    ],
    "description": "{rule_description}",
    "remediation": "{rule_remediation}",
    "ruleQuery": "armo_builtins"
}}
"""

exptected = """[{}]
"""

def generate_match_type(alert_object):
    if alert_object == "k8sApiObjects":
        return "match"
    elif alert_object == "externalObjects":
        return "dynamicMatch"

def generate_alert_object(alert_object):
    if alert_object == "k8sApiObjects":
        return set_k8s_api_objects.format(alert_object)
    elif alert_object == "externalObjects":
        return set_external_objects.format(alert_object)
    else:
        return ""

def create_expected_file(dirpath, test_name, alert_message, alert_score, failed_paths, fix_paths, fix_command, alert_object):
    with open(dirpath + '/' + 'expected.json', 'w') as f:
        f.write(generate_expected_file(test_name,
                            alert_message,
                            alert_score,
                            failed_paths,
                            fix_paths,
                            fix_command,
                            alert_object))

def generate_expected_file(test_name, alert_message, alert_score, failed_paths, fix_paths, fix_command, alert_object):
    # return empty expected if we are checking for success.
    if "success" in test_name:
        return exptected.format("")
    else:
        return exptected.format(msga.format(alert_message=alert_message,
                            alert_score=alert_score,
                            failed_paths=failed_paths,
                            fix_paths=fix_paths,
                            fix_command=fix_command,
                            alert_object=generate_alert_object(alert_object)))


def create_rule_metadata_file(dirpath, rule_name, action_required, host_sensor_rule, use_from_kubescape_version, use_until_kubescape_version, image_scan_related, match_type, rule_description, rule_remediation):
    with open(dirpath + '/' + 'rule.metadata.json', 'w') as f:
        f.write(generate_rule_metadata_file(rule_name,
                            action_required,
                            host_sensor_rule,
                            use_from_kubescape_version,
                            use_until_kubescape_version,
                            image_scan_related,
                            match_type,
                            rule_description,
                            rule_remediation))

def generate_use_from_kubescape_version(use_from_kubescape_version):
    if use_from_kubescape_version != '':
        return set_use_from_kubescape_version.format(use_from_kubescape_version=use_from_kubescape_version)
    else:
        return ''

def generate_use_until_kubescape_version(use_until_kubescape_version):
    if use_until_kubescape_version != '':
        return set_use_until_kubescape_version.format(use_until_kubescape_version=use_until_kubescape_version)
    else:
        return ''

def generate_rule_metadata_file(rule_name, action_required, host_sensor_rule, use_from_kubescape_version, use_until_kubescape_version, image_scan_related, alert_object, rule_description, rule_remediation):
    until_version = generate_use_until_kubescape_version(use_until_kubescape_version)
    from_version = generate_use_from_kubescape_version(use_from_kubescape_version)
    match_type = generate_match_type(alert_object)
    return rule_metadata.format(rule_name=rule_name,
                            action_required=action_required,
                            host_sensor_rule=host_sensor_rule,
                            use_from_kubescape_version=from_version,
                            use_until_kubescape_version=until_version,
                            image_scan_related=image_scan_related,
                            match_type=match_type,
                            rule_description=rule_description,
                            rule_remediation=rule_remediation)


# create_raw_rego_file create the raw.rego file undert the rule directory path specified.
# it uses generate_raw_rego to render the raw.rego file with custom values.
def create_raw_rego_file(dirpath, alert_message, alert_score, failed_paths, fix_paths, fix_command, alert_object):
    with open(dirpath + '/' + 'raw.rego', 'w') as f:
        f.write(generate_raw_rego(alert_message,
                            alert_score,
                            failed_paths,
                            fix_paths,
                            fix_command,
                            alert_object))


def generate_raw_rego(alert_message, alert_score, failed_paths, fix_paths, fix_command, alert_object):
    return raw_rego.format(msga.format(alert_message=alert_message,
                            alert_score=alert_score,
                            failed_paths=failed_paths,
                            fix_paths=fix_paths,
                            fix_command=fix_command,
                            alert_object=generate_alert_object(alert_object)))


# create_directory_if_not_exists checks if path provided exists and is a directory,
# if directory doesn't exists, then create it.
def create_directory_if_not_exists(dirpath):
    if path.exists(dirpath) and path.isdir(dirpath):
        return True
    os.mkdir(dirpath)
    return False


# validate_rule_name checks if the rule name provided in input
# matches the regex.
def validate_rule_name(name): 
    pattern = re.compile(regex)
    matches = pattern.match(name)
    if matches:
        return True
    return False


# define_args return arguments generated using argparse.
def define_args():
    parser = argparse.ArgumentParser(
                    prog=program_name,
                    description='{} helps you to '.format(program_name))
    parser.add_argument('--name',
                    type=str,
                    required=True,
                    help='Name of the rule you want to initialize.')
    parser.add_argument('--alert-message',
                    type=str,
                    default='',
                    help='alert message you want to return from rego rule.')
    parser.add_argument('--alert-score',
                    type=int,
                    default=7,
                    help='alert score you want to return from rego rule.')
    parser.add_argument('--failed-paths',
                    type=str,
                    default='',
                    help='failed paths you want to return from rego rule.')
    parser.add_argument('--fix-paths',
                    type=str,
                    default='',
                    help='fix paths you want to return from rego rule.')
    parser.add_argument('--fix-command',
                    type=str,
                    default='',
                    help='fix command you want to return from rego rule.')
    parser.add_argument('--alert-object',
                    type=str,
                    choices=['k8sApiObjects', 'externalObjects'],
                    default='k8sApiObjects',
                    help='alert objects you want to return from rego rule.')
    parser.add_argument('--action-required',
                    type=str,
                    choices=['manual review', 'configuration', 'requires review'],
                    default='',
                    help='attribute "actionRequired" you want to set on rule.metadata.json file.')
    parser.add_argument('--host-sensor-rule',
                    type=bool,
                    default=False,
                    action=argparse.BooleanOptionalAction,
                    help='attribute "hostSensorRule" you want to set on rule.metadata.json file.')
    parser.add_argument('--use-from-kubescape-version',
                    type=str,
                    default='',
                    help='attribute "useFromKubescapeVersion" you want to set on rule.metadata.json file.')
    parser.add_argument('--use-until-kubescape-version',
                    type=str,
                    default='',
                    help='attribute "useUntilKubescapeVersion" you want to set on rule.metadata.json file.')
    parser.add_argument('--image-scan-related',
                    type=bool,
                    default=False,
                    action=argparse.BooleanOptionalAction,
                    help='attribute "imageScanRelated" you want to set on rule.metadata.json file.')
    parser.add_argument('--rule-description',
                    type=str,
                    default='',
                    help='rule description you want to set on rule.metadata.json file.')
    parser.add_argument('--rule-remediation',
                    type=str,
                    default='',
                    help='rule remediation you want to set on rule.metadata.json file.')
    parser.add_argument('--test-list',
                    type=str,
                    default=test_list_default,
                    help='comma separated list of tests you want to provide on the rule. example: succes,failed')
    args = parser.parse_args()
    return args 


def main():
    args = define_args()
    rule_path = rules_base_path + '/' + args.name
    rule_test_path = rule_path + '/' + 'test'

    if not validate_rule_name(args.name):
        print("rule name doesn't match validation policy")
        sys.exit() 

    if create_directory_if_not_exists(rule_path):
        print("rule already exists")
        sys.exit() 

    create_raw_rego_file(rule_path,
                            args.alert_message,
                            args.alert_score,
                            args.failed_paths,
                            args.fix_paths,
                            args.fix_command,
                            args.alert_object)

    create_rule_metadata_file(rule_path,
                            args.name,
                            args.action_required,
                            f'{args.host_sensor_rule}'.lower(),
                            args.use_from_kubescape_version,
                            args.use_until_kubescape_version,
                            f'{args.image_scan_related}'.lower(),
                            args.alert_object,
                            args.rule_description,
                            args.rule_remediation)

    create_directory_if_not_exists(rule_test_path)

    # create directory for tests in list.
    for test in args.test_list.split(','):
        test_dir = rule_test_path + '/' + test
        test_dir_input = test_dir + '/' + 'input'
        create_directory_if_not_exists(test_dir)

        create_expected_file(test_dir,
                            test,
                            args.alert_message,
                            args.alert_score,
                            args.failed_paths,
                            args.fix_paths,
                            args.fix_command,
                            args.alert_object)

        create_directory_if_not_exists(test_dir_input)
 

if __name__ == "__main__":
    main()
