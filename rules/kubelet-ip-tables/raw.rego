package armo_builtins

import future.keywords.in

# --make-iptables-util-chains argument is present
deny[msga] {
	kubelet_info := input[_]
	kubelet_info.kind == "KubeletInfo"
	kubelet_info.apiVersion == "hostdata.kubescape.cloud/v1beta0"
	command := kubelet_info.data.cmdLine

	contains(command, "--make-iptables-util-chains")
	not contains(command, "--make-iptables-util-chains=true")

	external_obj := json.filter(kubelet_info, ["apiVersion", "data/cmdLine", "kind"])

	msga := {
		"alertMessage": "Argument --make-iptables-util-chains is not set to true.",
		"alertScore": 3,
		"failedPaths": [],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"externalObjects": external_obj},
	}
}

# --make-iptables-util-chains argument is not present, check in config file
deny[msga] {
	kubelet_info := input[_]
	kubelet_info.kind == "KubeletInfo"
	kubelet_info.apiVersion == "hostdata.kubescape.cloud/v1beta0"
	command := kubelet_info.data.cmdLine

	not contains(command, "--make-iptables-util-chains")
	contains(command, "--config")

	decodedConfigContent := base64.decode(kubelet_info.data.configFile.content)
	yamlConfig := yaml.unmarshal(decodedConfigContent)
	not yamlConfig.makeIPTablesUtilChains == true

	msga := {
		"alertMessage": "Property makeIPTablesUtilChains is not set to true",
		"alertScore": 3,
		"failedPaths": ["makeIPTablesUtilChains"],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"externalObjects": {
			"apiVersion": kubelet_info.apiVersion,
			"kind": kubelet_info.kind,
			"data": {"configFile": {"content": decodedConfigContent}},
		}}
	}
}
