package armo_builtins

import future.keywords.in

# CIS 4.2.9 https://workbench.cisecurity.org/sections/1126668/recommendations/1838656

# if --event-qps is present rule should pass
deny[msga] {
	obj := input[_]
	is_kubelet_info(obj)

	command := obj.data.cmdLine

	# "--event-qps" is DEPRECATED
	# not contains(command, "--event-qps")
	contains(command, "--config")

	decodedConfigContent := base64.decode(obj.data.configFile.content)
	yamlConfig := yaml.unmarshal(decodedConfigContent)
	yamlConfig.eventRecordQPS == 0

	msga := {
		"alertMessage": "Value of the eventRecordQPS argument is set to 0",
		"alertScore": 2,
		"reviewPaths": ["eventRecordQPS"],
		"failedPaths": ["eventRecordQPS"],
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

	# "--event-qps" is DEPRECATED
	# not contains(command, "--event-qps")
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

is_kubelet_info(obj) {
	obj.kind == "KubeletInfo"
	obj.apiVersion == "hostdata.kubescape.cloud/v1beta0"
}
