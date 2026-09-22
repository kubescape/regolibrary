# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

# CIS 4.2.14

# 4.2.14 is a Manual, unscored recommendation. CIS - and kube-bench's implementation of it -
# tests only that the parameter is SET, on the command line or in the kubelet config file, not
# that it holds a particular value. C-0284 (4.2.13), the adjacent Manual control, is written the
# same way. Checking for `true` here would make us stricter than the benchmark and would flag a
# bare `--seccomp-default`, which Go boolean flag syntax already means true.

deny contains msga if {
	some obj in input
	is_kubelet_info(obj)

	command := obj.data.cmdLine

	not seccomp_default_flag_set(command)
	contains(command, "--config")

	decodedConfigContent := base64.decode(obj.data.configFile.content)
	yamlConfig := yaml.unmarshal(decodedConfigContent)
	not seccomp_default_is_set(yamlConfig)

	msga := {
		"alertMessage": "Neither argument --seccomp-default nor seccompDefault is set.",
		"alertScore": 2,
		"reviewPaths": [],
		"failedPaths": [],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"externalObjects": {
			"apiVersion": obj.apiVersion,
			"kind": obj.kind,
			"metadata": obj.metadata,
			"data": {"configFile": {"content": decodedConfigContent}},
		}},
	}
}

deny contains msga if {
	some obj in input
	is_kubelet_info(obj)

	command := obj.data.cmdLine

	not seccomp_default_flag_set(command)
	not contains(command, "--config")

	external_obj := json.filter(obj, ["apiVersion", "data/cmdLine", "kind", "metadata"])

	msga := {
		"alertMessage": "Neither argument --seccomp-default nor seccompDefault is set.",
		"alertScore": 2,
		"reviewPaths": [],
		"failedPaths": [],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"externalObjects": external_obj},
	}
}

## Host sensor did not give us a config file we can read
deny contains msga if {
	some obj in input
	is_kubelet_info(obj)

	command := obj.data.cmdLine

	not seccomp_default_flag_set(command)
	contains(command, "--config")

	config_file_analysis_failed(obj)

	msga := {
		"alertMessage": "Failed to analyze config file",
		"alertScore": 2,
		"reviewPaths": [],
		"failedPaths": [],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"externalObjects": {
			"apiVersion": obj.apiVersion,
			"kind": obj.kind,
			"data": obj.data,
		}},
	}
}

# The sensor reported no content at all.
config_file_analysis_failed(obj) if {
	not obj.data.configFile.content
}

# The sensor reported content we cannot decode or parse. Without this branch the compliance
# rule above is simply undefined for such a kubelet and the control reports it as passing,
# which is the wrong way to fail: we would be claiming compliance we never established.
config_file_analysis_failed(obj) if {
	obj.data.configFile.content != ""
	not config_file_parses(obj)
}

config_file_parses(obj) if {
	decodedConfigContent := base64.decode(obj.data.configFile.content)
	_ = yaml.unmarshal(decodedConfigContent)
}

# Existence check, not a truthiness check: `seccompDefault: false` is still set, and a
# truthiness test would deny it.
seccomp_default_is_set(yamlConfig) if {
	_ = yamlConfig.seccompDefault
}

# Matched as a whole argument rather than with `contains`, so that an unrelated value that
# merely embeds the text - a `--config` path containing "--seccomp-default", say - is not read
# as the flag being present. Covers `--seccomp-default`, `--seccomp-default=true` and the
# space-separated form.
#
# Note the deliberate asymmetry with the `--config` checks above, which stay substring matches:
# kubelet also accepts `--config-dir` for drop-in configuration, and a kubelet started that way
# still has a config file for the sensor to read. Narrowing `--config` to a whole-argument match
# would push those hosts down the "no config file" branch and alert on them even when the
# drop-in config sets seccompDefault.
seccomp_default_flag_set(command) if {
	regex.match(`(^|[[:space:]])--seccomp-default(=|[[:space:]]|$)`, command)
}

is_kubelet_info(obj) if {
	obj.kind == "KubeletInfo"
	obj.apiVersion == "hostdata.kubescape.cloud/v1beta0"
}
