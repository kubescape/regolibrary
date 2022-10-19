package armo_builtins

import future.keywords.in

#CIS 4.2.6 https://workbench.cisecurity.org/sections/1126668/recommendations/1838648

deny[msga] {
	obj := input[_]
	is_kubelet_info(obj)

	command := obj.data.cmdLine

	contains(command, "--protect-kernel-defaults")
	not contains(command, "--protect-kernel-defaults=true")

	external_obj := json.filter(obj, ["apiVersion", "data/cmdLine", "kind"])

	msga := {
		"alertMessage": "Argument --protect-kernel-defaults is not set to true.",
		"alertScore": 2,
		"failedPaths": [],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"alertObject": external_obj},
	}
}

deny[msga] {
	obj := input[_]
	is_kubelet_info(obj)

	command := obj.data.cmdLine

	not contains(command, "--protect-kernel-defaults")
	contains(command, "--config")

	decodedConfigContent := base64.decode(obj.data.configFile.content)
	yamlConfig := yaml.unmarshal(decodedConfigContent)
	not yamlConfig.protectKernelDefaults == true

	msga := {
		"alertMessage": "Property protectKernelDefaults is not set to true",
		"alertScore": 2,
		"failedPaths": ["protectKernelDefaults"],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"externalObjects": {
			"apiVersion": obj.apiVersion,
			"kind": obj.kind,
			"data": {"configFile": {"content": decodedConfigContent}},
		}},
	}
}

deny[msga] {
	obj := input[_]
	is_kubelet_info(obj)

	command := obj.data.cmdLine

	not contains(command, "--protect-kernel-defaults")
	not contains(command, "--config")

	external_obj := json.filter(obj, ["apiVersion", "data/cmdLine", "kind"])

	msga := {
		"alertMessage": "Argument --protect-kernel-defaults is not set to true.",
		"alertScore": 2,
		"failedPaths": [],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"alertObject": external_obj},
	}
}

## Host sensor failed to get config file content
deny[msga] {
	obj := input[_]
	is_kubelet_info(obj)

	command := obj.data.cmdLine

	not contains(command, "--protect-kernel-defaults")
	contains(command, "--config")

	not obj.data.configFile.content

	msga := {
		"alertMessage": "Failed to analyze config file",
		"alertScore": 2,
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

is_kubelet_info(obj) {
	obj.kind == "KubeletInfo"
	obj.apiVersion == "hostdata.kubescape.cloud/v1beta0"
}
