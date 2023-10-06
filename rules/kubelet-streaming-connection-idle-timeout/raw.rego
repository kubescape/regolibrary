package armo_builtins

import future.keywords.in

# CIS 4.2.5 https://workbench.cisecurity.org/sections/1126668/recommendations/1838646

deny[msga] {
	obj := input[_]
	is_kubelet_info(obj)

	command := obj.data.cmdLine

	contains(command, "--streaming-connection-idle-timeout")
	contains(command, "--streaming-connection-idle-timeout=0")

	external_obj := json.filter(obj, ["apiVersion", "data/cmdLine", "kind", "metadata"])

	msga := {
		"alertMessage": "Timeouts on streaming connections are enabled",
		"alertScore": 3,
		"failedPaths": [],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": external_obj
	}
}

deny[msga] {
	obj := input[_]
	is_kubelet_info(obj)

	command := obj.data.cmdLine

	not contains(command, "--streaming-connection-idle-timeout")
	contains(command, "--config")

	decodedConfigContent := base64.decode(obj.data.configFile.content)
	yamlConfig := yaml.unmarshal(decodedConfigContent)
	yamlConfig.streamingConnectionIdleTimeout == 0

	msga := {
		"alertMessage": "Timeouts on streaming connections are enabled",
		"alertScore": 3,
		"failedPaths": ["streamingConnectionIdleTimeout"],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"externalObjects": {
			"apiVersion": obj.apiVersion,
			"kind": obj.kind,
			"metadata": obj.metadata,
			"data": {"configFile": {"content": decodedConfigContent}},
		}}
	}
}

## Host sensor failed to get config file content
deny[msga] {
	obj := input[_]
	is_kubelet_info(obj)

	command := obj.data.cmdLine

	not contains(command, "--streaming-connection-idle-timeout")
	contains(command, "--config")

	not obj.data.configFile.content

	msga := {
		"alertMessage": "Failed to analyze config file",
		"alertScore": 3,
		"failedPaths": [],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"externalObjects": {
			"apiVersion": obj.apiVersion,
			"kind": obj.kind,
			"data": obj.data
		}}
	}
}

is_kubelet_info(obj) {
	obj.kind == "KubeletInfo"
	obj.apiVersion == "hostdata.kubescape.cloud/v1beta0"
}
