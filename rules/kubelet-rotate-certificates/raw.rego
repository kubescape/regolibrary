package armo_builtins

import future.keywords.in

# CIS 4.2.11 https://workbench.cisecurity.org/sections/1126668/recommendations/1838658

deny[msga] {
	obj := input[_]
	is_kubelet_info(obj)

	command := obj.data.cmdLine

	contains(command, "--rotate-certificates")
	not contains(command, "--rotate-certificates=true")

	external_obj := json.filter(obj, ["apiVersion", "data/cmdLine", "kind", "metadata"])

	msga := {
		"alertMessage": "Kubelet client certificates rotation is disabled",
		"alertScore": 6,
		"failedPaths": [],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"externalObjects": external_obj},
	}
}

deny[msga] {
	obj := input[_]
	is_kubelet_info(obj)

	command := obj.data.cmdLine

	not contains(command, "--rotate-certificates")
	contains(command, "--config")

	decodedConfigContent := base64.decode(obj.data.configFile.content)
	yamlConfig := yaml.unmarshal(decodedConfigContent)
	yamlConfig.rotateCertificates == false

	msga := {
		"alertMessage": "Kubelet client certificates rotation is disabled",
		"alertScore": 6,
		"failedPaths": ["rotateCertificates"],
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

## Host sensor failed to get config file content
deny[msga] {
	obj := input[_]
	is_kubelet_info(obj)

	command := obj.data.cmdLine

	not contains(command, "--rotate-certificates")
	contains(command, "--config")

	not obj.data.configFile.content

	msga := {
		"alertMessage": "Failed to analyze config file",
		"alertScore": 6,
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
