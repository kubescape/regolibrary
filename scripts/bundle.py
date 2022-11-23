import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from os import path

import requests
import yaml


# Bundle
BUNDLE_NAME = 'kubescape_regolibrary_bundle'
BUNDLE_ARTIFACTS = 'modules rules controls frameworks data.json'

# Utils
OPA_UTILS_MODULES_URL = 'https://raw.githubusercontent.com/kubescape/opa-utils/master/resources/dependencies.go'
PACKAGE_REGEX = r"package\s+?(\S+)"

# Dirs
RULES_DIR = 'rules'
CONTROLS_DIR = 'controls'
FRAMEWORKS_DIR = 'frameworks'


# Templates
CONTROL_TEMPLATE = \
    """package armo_builtins.controls.{control_id}

deny := data.armo_builtins.controls.control_msg(rules, rego.metadata.rule().custom){{
    rules := [msg | msg := data.armo_builtins.controls.{control_id}.rules[_][i]]
}}

{rules}
"""

CONTROL_MESSAGE_REGO = \
    """package armo_builtins.controls

control_msg(rules, metadata) := msgs {{
    data.settings.verbose
    msgs := [object.union(rule, metadata) |
        rule := rules[_]
    ]
}} else := msg {{
    data.settings.metadata
    msg := object.union({{"results": rules}},  metadata)
}} else := rules

"""

FRAMEWORK_TEMPLATE = \
    """package armo_builtins.frameworks.{framework_name}

deny := data.armo_builtins.frameworks.framework_msg(controls, rego.metadata.rule().custom) {{
    count(controls) > 0
}}

{controls}
"""

FRAMEWORK_MESSAGE_REGO = \
    """package armo_builtins.frameworks

framework_msg(controls, metadata) := msgs {{
    data.settings.verbose
    msgs := [object.union(msg, {{"framework":metadata.name, "frameworkDescription":metadata.description}}) |
        msg := controls[id][i]
    ]
}} else := msg {{
    data.settings.metadata
    msg := object.union({{"results": controls}},  metadata)
}} else := simple {{
    simple := [msg |
        msg := controls[i][j]
    ]
}}
"""

# TODO: Add framework subsection information


removed_controls = list()
removed_rules = list()


def normalize_rule_name(name) -> str:
    """
    Normalize rule name to be used as a package name

    :param name: rule name

    :return: normalized rule name
    """
    return re.sub(r'[^a-zA-Z0-9_]', '_', name)


def copy_rules(regolibrary_path, dst) -> None:
    """
    Copy rules from the regolibrary repo.

    :param regolibrary_path: path to the regolibrary directory
    :param dst: path to the destination directory
    """
    shutil.copytree(path.join(regolibrary_path, RULES_DIR),
                    path.join(dst, RULES_DIR))


def copy_modules(regolibrary_path, dst) -> None:
    """
    Copy utilities rego modules.
    Currently, we are using the modules from opa-utils repo.
    Ideally, we should have them in the regolibrary repo, under `/modules`.

    :param regolibrary_path: path to the regolibrary directory
    :param dst: path to the destination directory
    """
    # First try to copy the modules from the regolibrary
    regolibrary_modules_path = path.join(regolibrary_path, 'modules')
    if path.exists(regolibrary_modules_path):
        shutil.copytree(regolibrary_modules_path, path.join(dst, 'modules'))
        return

    # If the modules are not in the regolibrary, try to copy them from the opa-utils package
    rs = requests.get(OPA_UTILS_MODULES_URL)
    assert rs.status_code == 200, f'Failed to download modules from {OPA_UTILS_MODULES_URL}'

    multi_line_var_regex = r"var\s+?\S+\s+?=\s+?`[\s+?\n]?([^`]+)`"
    for match in re.finditer(multi_line_var_regex, rs.text, re.MULTILINE):
        content = match.group(1)
        package_name = re.search(PACKAGE_REGEX, content).group(1)
        module_path = path.join(dst, 'modules', f'{package_name}.rego')
        os.makedirs(path.dirname(module_path), exist_ok=True)
        with open(module_path, 'w') as f:
            f.write(content)


def rename_packages(rules_path) -> None:
    """
    Rename rules packages to avoid conflicts with other packages.
    armo_builtins -> armo_builtins.{rule_name}.{file_name} (file_name is raw and filter, normally)

    :param rules_path: path to the rules directory
    """
    for root, dirs, files in os.walk(rules_path):
        # first, get rule name from rule.metadata.json
        if not 'rule.metadata.json' in files:
            continue
        for file in files:
            if file == 'rule.metadata.json':
                with open(path.join(root, file)) as f:
                    metadata = json.load(f)
                    rule_name = metadata['name']
                    break

        # Normalize rule name
        rule_name = normalize_rule_name(rule_name)

        # Rename package names
        for file in files:
            filename, file_extension = path.splitext(file)
            if not file_extension == '.rego':
                continue
            with open(path.join(root, file)) as f:
                content = f.read()
            content = re.sub(
                PACKAGE_REGEX, f"package armo_builtins.rules.{rule_name}.{filename}", content)
            with open(path.join(root, file), 'w') as f:
                f.write(content)


def remove_invalid_rules(rules_path) -> None:
    """
    Remove rules that are using invalid functions

    :param rules_path: path to the rules directory
    """
    invalid_strings = [
        'armo.',  # armo functions are not supported in official OPA
    ]
    for root, _, files in os.walk(rules_path):
        for file in files:
            _, file_extension = path.splitext(file)
            if not file_extension == '.rego':
                continue
            with open(path.join(root, file)) as f:
                content = f.read()
            for invalid_string in invalid_strings:
                if invalid_string in content:
                    os.remove(path.join(root, file))
                    with open(path.join(root, 'rule.metadata.json')) as f:
                        metadata = json.load(f)
                    removed_rules.append(metadata['name'])
                    break


def add_metadata_to_rego(path, metadata, use_custom=True, scope="rule", entrypoint=True) -> None:
    """
    Add metadata to rego files
    https://www.openpolicyagent.org/docs/latest/annotations/

    :param path: Path to the rego file
    :param metadata: Metadata to add
    :param use_custom: If true, add metadata to custom field
    :param scope: Scope of the metadata. Can be rule, package or file
    :param entrypoint: If true, add metadata to the entrypoint
    """

    if use_custom:
        metadata = {
            'custom': metadata,
        }
    metadata["scope"] = scope if not metadata.get(
        "scope") else metadata["scope"]

    if entrypoint:
        metadata["entrypoint"] = True

    # Construct rego annotation string
    metadata = yaml.dump(metadata)
    metadata_lines = metadata.splitlines()
    metadata_lines = [f'# {line}' for line in metadata_lines]
    metadata_lines = ["", "# METADATA"] + metadata_lines + [""]

    # Read rego file
    with open(path) as f:
        rego_content = f.read()

    # Find the right place to insert the metadata

    rego_lines = rego_content.splitlines()
    for i, line in enumerate(rego_lines):
        line = line.strip()
        if not line.startswith('package') and \
                not line.startswith('import') and \
                not line.startswith('#') and \
                line != '':
            break

    # Insert the metadata
    rego_lines = rego_lines[:i] + metadata_lines + rego_lines[i:]
    rego_content = '\n'.join(rego_lines)

    # Write the file
    with open(path, 'w') as f:
        f.write(rego_content)


def add_metadata_to_rule(rule_dir) -> None:
    """
    Add OPA rules metadata to regolibrary rules, using the metadata from the `rule.metadata.json` file
    https://www.openpolicyagent.org/docs/latest/annotations/

    :param rule_dir: Path to the rule directory
    """

    # get metadata
    metadata_path = path.join(rule_dir, 'rule.metadata.json')
    with open(metadata_path) as f:
        metadata = json.load(f)

    rego_file_path = path.join(rule_dir, 'raw.rego')
    if not path.exists(rego_file_path):
        return

    add_metadata_to_rego(rego_file_path, metadata)


def add_metadata_to_rules(rules_path) -> None:
    """
    Add OPA rules metadata to regolibrary rules
    https://www.openpolicyagent.org/docs/latest/annotations/

    :param rules_path: Path to the rules directory
    """
    for root, _, files in os.walk(rules_path):
        if 'rule.metadata.json' in files:
            add_metadata_to_rule(root)


def generate_controls(regolibrary_path, dst) -> None:
    """
    Generate controls from regolibrary.

    :param regolibrary_path: Path to the regolibrary directory
    :param dst: Path to the destination directory
    """
    src_controls_path = path.join(regolibrary_path, CONTROLS_DIR)
    controls_path = path.join(dst, CONTROLS_DIR)
    os.makedirs(controls_path, exist_ok=True)

    # Controls message rego utility
    with open(path.join(controls_path, 'utils.rego'), 'w') as f:
        f.write(CONTROL_MESSAGE_REGO.format())

    # Generate and enrich controls rego files
    for file_name in os.listdir(src_controls_path):
        src_file_path = path.join(src_controls_path, file_name)
        if path.isdir(src_file_path) or not file_name.endswith('.json'):
            continue

        # Load metadata
        with open(src_file_path) as f:
            metadata = json.load(f)

        # Destination file path
        dst_file_name, _ = path.splitext(file_name)
        dst_file_name = f'{dst_file_name}.rego'
        dst_file_path = path.join(controls_path, dst_file_name)

        # Generate rego file
        control_rego = generate_control(metadata)
        if not control_rego:
            global removed_controls
            removed_controls.append(metadata['name'])
            continue

        with open(dst_file_path, 'w') as f:
            f.write(control_rego)

        # Enrich rego file with metadata
        add_metadata_to_rego(dst_file_path, metadata)


def generate_control(metadata) -> str:
    """
    Generate a rego file for a control.

    :param metadata: Control metadata

    :return: Control Rego file content
    """
    rules = []

    global removed_rules
    if len([rule for rule in metadata['rulesNames'] if rule in removed_rules]) > 0:
        return ""

    for rule in metadata['rulesNames']:
        rule = normalize_rule_name(rule)
        rules.append(f"rules[data.armo_builtins.rules.{rule}.raw.deny]")
    assert len(
        rules) > 0, f'No rules found for control ({metadata["id"]}) "{metadata["name"]}" '
    rules = '\n'.join(rules)
    control_id = normalize_rule_name(metadata['controlID'])
    return CONTROL_TEMPLATE.format(control_id=control_id, rules=rules)
    # TODO: .filter rules


def find_control_by_name(controls_dir, name) -> dict:
    """
    Find a control by its name.

    :param controls_dir: Path to the controls directory
    :param name: Name of the control

    :return: Control metadata
    """
    for file_name in os.listdir(controls_dir):
        if not file_name.endswith('.json'):
            continue
        with open(path.join(controls_dir, file_name)) as f:
            control = json.load(f)
        if control['name'] == name:
            return control


def generate_framework(regolibrary_path, metadata) -> str:
    """
    Generate the framework rego file

    :param regolibrary_path: Path to the regolibrary directory
    :param metadata: Metadata of the framework

    :return: Framework rego file content
    """
    global removed_controls

    controls = []
    controls_path = path.join(regolibrary_path, CONTROLS_DIR)
    for control_name in metadata['controlsNames']:
        if control_name in removed_controls:
            continue
        control = find_control_by_name(controls_path, control_name)
        if not control:
            print(
                f"WARNING: Framework: '{metadata['name']}' Cannot find control: '{control_name}'")
            continue
        ctrl_id = normalize_rule_name(control['controlID'])
        controls.append(
            f'controls["{ctrl_id}"] := data.armo_builtins.controls.{ctrl_id}.deny')

    assert len(
        controls) > 0, f'No controls found for framework "{metadata["name"]}" '
    controls = '\n'.join(controls)
    framework_name = normalize_rule_name(metadata['name'])

    # TODO: Framework subsections
    return FRAMEWORK_TEMPLATE.format(framework_name=framework_name, controls=controls)


def generate_frameworks(regolibrary_path, dst):
    """
    Generate frameworks rego files

    :param regolibrary_path: Path to the regolibrary directory
    :param dst: Path to the destination directory
    """
    frameworks_path = path.join(dst, FRAMEWORKS_DIR)
    os.makedirs(frameworks_path, exist_ok=True)

    # Frameworks message rego utility
    with open(path.join(frameworks_path, 'utils.rego'), 'w') as f:
        f.write(FRAMEWORK_MESSAGE_REGO.format())

    # Generate and enrich frameworks rego files
    for file_name in os.listdir(path.join(regolibrary_path, FRAMEWORKS_DIR)):

        # Load metadata
        src_file_path = path.join(regolibrary_path, FRAMEWORKS_DIR, file_name)
        if path.isdir(src_file_path) or not file_name.endswith('.json'):
            continue
        with open(src_file_path) as f:
            metadata = json.load(f)

        # Destination file path
        dst_file_name, _ = path.splitext(file_name)
        dst_file_name = f'{dst_file_name}.rego'
        dst_file_path = path.join(frameworks_path, dst_file_name)

        # Generate rego file
        with open(dst_file_path, 'w') as f:
            f.write(generate_framework(regolibrary_path, metadata))

        # Enrich rego file with metadata
        add_metadata_to_rego(dst_file_path, metadata)


def clear_build_dir(build_dir):
    """
    Remove any file that is not a rego file
    so the `/data.json` will include only wanted data

    :param build_dir: Path to the build directory
    """
    for root, dirs, files in os.walk(build_dir):
        for file in files:
            if not file.endswith('.rego'):
                os.remove(path.join(root, file))


def add_default_settings(regolibrary_path, build_dir):
    """
    Add default settings to the `data.json` file, including the default controls inputs

    :param regolibrary_path: Path to the rego library
    :param build_dir: Path to the build directory
    """
    with open(path.join(regolibrary_path, 'default-config-inputs.json')) as f:
        data = json.load(f)

    bundle_data = data['settings']  # -> Contain only postureControlInputs

    # See controls and frameworks templates
    bundle_data['settings'] = {
        'metadata': True,
        'verbose': False,
    }

    with open(path.join(build_dir, 'data.json'), 'w') as f:
        json.dump(bundle_data, f, indent=2)


def run_cmd(cmd, verbose=False):
    """
    Run a system command.

    :param cmd: Command to run
    :param verbose: Print command output
    """
    if verbose:
        print(cmd)
    p = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if verbose:
        for line in p.stdout.readlines():
            print(line.decode('utf-8'), end='')
            sys.stdout.flush()

    for line in p.stderr.readlines():
        print(line.decode('utf-8'), end='')
        sys.stderr.flush()

    retval = p.wait()
    if retval != 0:
        raise Exception(f'Failed to run command: {cmd}')


def collect_entrypoints(dir) -> list:
    """
    Collect Rego entrypoints, since it seems that the `entrypoint` annotation is not working.

    :param dir: Path to the directory to search for entrypoints

    :return: List of entrypoints
    """
    entry_points = set()
    for root, dirs, files in os.walk(dir):
        for file in files:
            if not file.endswith('.rego'):
                continue
            with open(path.join(root, file)) as f:
                content = f.read()
            package_name = re.search(PACKAGE_REGEX, content).group(1)
            entry_point = package_name.replace('.', '/')
            entry_points.add(entry_point)
    return entry_points


def bundle_rego(opa_path, library_path, dst, verbose=False):
    """
    Bundle rego files into a single file in the OPA bundle format.

    :param opa_path: Path to the OPA binary
    :param library_path: Path to the rego library
    :param dst: Path to the destination directory
    :param verbose: Print OPA output
    """
    cwd = os.getcwd()
    os.chdir(library_path)

    cmd = f'{opa_path} build {BUNDLE_ARTIFACTS} --output {dst}'
    run_cmd(cmd, verbose=verbose)

    os.chdir(cwd)


def bundle_wasm(opa_path, library_path, dst, verbose=False):
    """
    Bundle rego files into a single file in the OPA bundle format and wasm target.

    :param opa_path: Path to the OPA binary
    :param library_path: Path to the rego library
    :param dst: Path to the destination directory
    :param verbose: Print OPA output
    """
    cwd = os.getcwd()
    os.chdir(library_path)

    entrypoints = list(collect_entrypoints(library_path))
    entrypoints += ['armo_builtins/controls', 'armo_builtins/frameworks']
    entrypoints = ' -e '.join(entrypoints)

    cmd = f'{opa_path} build --prune-unused -t wasm {BUNDLE_ARTIFACTS} --output {dst} -e {entrypoints}'
    run_cmd(cmd, verbose=verbose)

    os.chdir(cwd)


def main(library_path, dst):
    """
    Build the rego library bundles

    :param library_path: Path to the rego library
    :param dst: Destination directory
    """
    tempdir = tempfile.mkdtemp()
    try:
        # Prepare rules
        copy_modules(library_path, tempdir)
        copy_rules(library_path, tempdir)
        rename_packages(tempdir)
        add_metadata_to_rules(path.join(tempdir, RULES_DIR))
        remove_invalid_rules(path.join(tempdir, RULES_DIR))

        # Prepare controls and frameworks
        generate_controls(library_path, tempdir)
        generate_frameworks(library_path, tempdir)

        # Set the /data.json file
        clear_build_dir(tempdir)
        add_default_settings(library_path, tempdir)

        # Build
        bundle_rego("opa", tempdir, path.join(
            dst, f'{BUNDLE_NAME}.tar.gz'), verbose=True)
        bundle_wasm("opa",  tempdir, path.join(
            dst, f'{BUNDLE_NAME}_wasm.tar.gz'))

    finally:
        shutil.rmtree(tempdir) if False else None


def cli():
    parser = argparse.ArgumentParser(
        description="Build regolibrary policy-rules OPA bundles")
    parser.add_argument('regolibrary_path', help='Path to regolibrary')
    parser.add_argument('-o', '--output', help='Output directory', default='.')
    parser.add_argument(
        '--removed-out', help='Output file for removed rules and controls', default=None)
    parser.add_argument(
        '--edit-readme', help='Edit the README.md file', action='store_true')
    args = parser.parse_args()

    main(args.regolibrary_path, path.abspath(args.output))

    print(f'SUCCESS: Bundle created at {args.output}')
    if removed_rules:
        print(f'\nBundles does not support the following rules and controls:')
        print(f'Rules:')
        for rule in removed_rules:
            print(f'\t{rule}')
        print(f'Controls:')
        for rule in removed_controls:
            print(f'\t{rule}')
        if args.removed_out:
            with open(args.removed_out, 'w') as f:
                json.dump({
                    'rules': list(removed_rules),
                    'controls': list(removed_controls),
                }, f, indent=2)

        if args.edit_readme:
            # Add removed rules and controls to the README.md file
            with open(path.join(args.regolibrary_path, 'README.md'), 'r') as f:
                readme = f.read()

            rules_start = "<!-- Start of OPA bundles removed rules -->"
            rules_end = "<!-- End of OPA bundles removed rules -->"
            controls_start = "<!-- Start of OPA bundles removed controls -->"
            controls_end = "<!-- End of OPA bundles removed controls -->"

            # replace using regex
            # rules
            rules = '\n- '.join(removed_rules)
            readme = re.sub(f'{rules_start}.*{rules_end}', f'{rules_start}\n- {rules}\n{rules_end}', readme, flags=re.DOTALL)

            # controls
            for i, ctrl_name in enumerate(removed_controls):
                ctrl_metadata = find_control_by_name(path.join(args.regolibrary_path, CONTROLS_DIR), ctrl_name)
                removed_controls[i] = f'{ctrl_metadata["controlID"]} - {ctrl_name}'
            ctrls = '\n- '.join(removed_controls)
            readme = re.sub(f'{controls_start}.*{controls_end}', f'{controls_start}\n- {ctrls}\n{controls_end}', readme, flags=re.DOTALL)

            with open(path.join(args.regolibrary_path, 'README.md'), 'w') as f:
                f.write(readme)


if __name__ == '__main__':
    cli()
