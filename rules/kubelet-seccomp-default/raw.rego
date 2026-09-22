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

	not contains(command, "--seccomp-default")
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

	not contains(command, "--seccomp-default")
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

## Host sensor failed to get config file content
deny contains msga if {
	some obj in input
	is_kubelet_info(obj)

	command := obj.data.cmdLine

	not contains(command, "--seccomp-default")
	contains(command, "--config")

	not obj.data.configFile.content

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

# Existence check, not a truthiness check: `seccompDefault: false` is still set, and a
# truthiness test would deny it.
seccomp_default_is_set(yamlConfig) if {
	_ = yamlConfig.seccompDefault
}

is_kubelet_info(obj) if {
	obj.kind == "KubeletInfo"
	obj.apiVersion == "hostdata.kubescape.cloud/v1beta0"
}
