package armo_builtins

import future.keywords.in

# --streaming-connection-idle-timeout argument is present
deny[msga] {
	kubelet_info := input[_]
	kubelet_info.kind == "KubeletInfo"
	kubelet_info.apiVersion == "hostdata.kubescape.cloud/v1beta0"
	command := kubelet_info.data.cmdLine

	contains(command, "--streaming-connection-idle-timeout")
	contains(command, "--streaming-connection-idle-timeout=0")

	external_obj := json.filter(kubelet_info, ["apiVersion", "data/cmdLine", "kind"])

	msga := {
		"alertMessage": "Timeouts on streaming connections are enabled",
		"alertScore": 3,
		"failedPaths": [],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": external_obj
	}
}

# --protect-kernel-defaults argument is not present, check in config file
deny[msga] {
	kubelet_info := input[_]
	kubelet_info.kind == "KubeletInfo"
	kubelet_info.apiVersion == "hostdata.kubescape.cloud/v1beta0"
	command := kubelet_info.data.cmdLine

	not contains(command, "--streaming-connection-idle-timeout")
	contains(command, "--config")

	decodedConfigContent := base64.decode(kubelet_info.data.configFile.content)
	yamlConfig := yaml.unmarshal(decodedConfigContent)
	yamlConfig.streamingConnectionIdleTimeout == 0

	msga := {
		"alertMessage": "Timeouts on streaming connections are enabled",
		"alertScore": 3,
		"failedPaths": ["streamingConnectionIdleTimeout"],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"externalObjects": {
			"apiVersion": kubelet_info.apiVersion,
			"kind": kubelet_info.kind,
			"data": {"configFile": {"content": decodedConfigContent}},
		}}
	}
}
