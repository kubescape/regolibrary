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
	not config_dir_flag_set(command)
	config_flag_set(command)

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
	not config_dir_flag_set(command)
	not config_flag_set(command)

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
	not config_dir_flag_set(command)
	config_flag_set(command)

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

## Kubelet uses drop-in configuration the host sensor does not collect
#
# host-scanner and node-agent both resolve the config file with GetArg("--config"), which
# matches only `--config=<path>` or `--config <path>`; `--config-dir` never matches it. When
# `--config` is absent they fall back to a default path (/var/lib/kubelet/config.yaml, or the
# EKS path), and neither collector reads or merges the drop-in directory.
#
# So for a kubelet using `--config-dir` the file we were handed is not the effective
# configuration: with drop-ins only, it is a file the kubelet never read, and with both flags
# it is the base layer without the overrides. Deciding compliance from it would assert a result
# we cannot support in either direction. We report it for manual review instead, which keeps
# the presence semantics honest until the sensor supplies merged configuration.
#
# There is deliberately no exemption for a base file that already sets the parameter. Drop-ins
# are applied with jsonpatch.MergePatch (cmd/kubelet/app/server.go), so under RFC 7386 a later
# `.conf` containing `seccompDefault: null` removes the key outright; SeccompDefault is a *bool
# that then defaults to false. Presence in the base file therefore does not imply presence in
# the merged configuration, and treating it as decidable would reintroduce a false pass.
deny contains msga if {
	some obj in input
	is_kubelet_info(obj)

	command := obj.data.cmdLine

	not seccomp_default_flag_set(command)
	config_dir_flag_set(command)

	msga := {
		"alertMessage": "Cannot determine whether seccompDefault is set: the kubelet is configured with --config-dir, and the host sensor does not collect drop-in configuration. Review the merged kubelet configuration manually.",
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

# Whole-argument matches rather than `contains`, so that a value which merely embeds the text -
# a `--config` path containing "--seccomp-default", say - is not read as the flag being present,
# and so that `--config-dir` is not mistaken for `--config`. The `--config` pattern deliberately
# mirrors the collectors' own GetArg: `--config=<path>`, `--config <path>` or the bare flag.
seccomp_default_flag_set(command) if {
	regex.match(`(^|[[:space:]])--seccomp-default(=|[[:space:]]|$)`, command)
}

config_flag_set(command) if {
	regex.match(`(^|[[:space:]])--config(=|[[:space:]]|$)`, command)
}

config_dir_flag_set(command) if {
	regex.match(`(^|[[:space:]])--config-dir(=|[[:space:]]|$)`, command)
}

is_kubelet_info(obj) if {
	obj.kind == "KubeletInfo"
	obj.apiVersion == "hostdata.kubescape.cloud/v1beta0"
}
