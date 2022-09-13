package armo_builtins

import future.keywords.in

# Argument set via CLI
deny[msga] {
	kubelet_info := input[_]
	kubelet_info.kind == "KubeletInfo"
	kubelet_info.apiVersion == "hostdata.kubescape.cloud/v1beta0"
	command := kubelet_info.data.cmdLine

	contains(command, "--read-only-port")
	not contains(command, "--read-only-port=0")

	external_obj := json.filter(kubelet_info, ["apiVersion", "data/cmdLine", "kind"])


	msga := {
		"alertMessage": "kubelet read-only port is not disabled",
		"alertScore": 4,
		"failedPaths": [],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": external_obj
	}
}

# Property set via config file
deny[msga] {
	kubelet_info := input[_]
	kubelet_info.kind == "KubeletInfo"
	kubelet_info.apiVersion == "hostdata.kubescape.cloud/v1beta0"
	command := kubelet_info.data.cmdLine

	not contains(kubelet_info, "--read-only-port")
	contains(command, "--config")

	decodedConfigContent := base64.decode(kubelet_info.data.configFile.content)
    yamlConfig := yaml.unmarshal(decodedConfigContent)

	yamlConfig.readOnlyPort
	not yamlConfig.readOnlyPort == 0

	msga := {
		"alertMessage": "kubelet read-only port is not disabled",
		"alertScore": 4,
		"failedPaths": ["readOnlyPort"],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"externalObjects": {
			"apiVersion": kubelet_info.apiVersion,
			"kind": kubelet_info.kind,
			"data": {"configFile": {"content": decodedConfigContent}},
		}}
	}
}
