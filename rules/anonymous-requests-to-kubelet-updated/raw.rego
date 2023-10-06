package armo_builtins

# CIS 4.2.1 https://workbench.cisecurity.org/sections/1126668/recommendations/1838638

deny[msga] {
	obj := input[_]
	is_kubelet_info(obj)
	command := obj.data.cmdLine

	contains(command, "--anonymous-auth")
	contains(command, "--anonymous-auth=true")

	external_obj := json.filter(obj, ["apiVersion", "data/cmdLine", "kind", "metadata"])

	msga := {
		"alertMessage": "Anonymous requests is enabled.",
		"alertScore": 7,
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

	not contains(command, "--anonymous-auth")
	not contains(command, "--config")

	external_obj := json.filter(obj, ["apiVersion", "data/cmdLine", "kind", "metadata"])

	msga := {
		"alertMessage": "Anonymous requests is enabled.",
		"alertScore": 7,
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

	not contains(command, "--anonymous-auth")
	contains(command, "--config")

	decodedConfigContent := base64.decode(obj.data.configFile.content)
	yamlConfig := yaml.unmarshal(decodedConfigContent)
	not yamlConfig.authentication.anonymous.enabled == false

	msga := {
		"alertMessage": "Anonymous requests is enabled.",
		"alertScore": 7,
		"reviewPaths": ["authentication.anonymous.enabled"],
		"failedPaths": ["authentication.anonymous.enabled"],
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

	not contains(command, "--anonymous-auth")
	contains(command, "--config")

	not obj.data.configFile.content

	msga := {
		"alertMessage": "Failed to analyze config file",
		"alertScore": 7,
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
