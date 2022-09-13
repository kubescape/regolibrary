package armo_builtins

import future.keywords.in

# --rotate-certificates argument is present
deny[msga] {
	kubelet_info := input[_]
	kubelet_info.kind == "KubeletInfo"
	kubelet_info.apiVersion == "hostdata.kubescape.cloud/v1beta0"
	command := kubelet_info.data.cmdLine

	contains(command, "--rotate-certificates")
	not contains(command, "--rotate-certificates=true")

	external_obj := json.filter(kubelet_info, ["apiVersion", "data/cmdLine", "kind"])

	msga := {
		"alertMessage": "Kubelet client certificates rotation is disabled",
		"alertScore": 6,
		"failedPaths": [],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"externalObjects": external_obj},
	}
}

# --rotate-certificates argument is not present, check in config file
deny[msga] {
	kubelet_info := input[_]
	kubelet_info.kind == "KubeletInfo"
	kubelet_info.apiVersion == "hostdata.kubescape.cloud/v1beta0"
	command := kubelet_info.data.cmdLine

	not contains(command, "--rotate-certificates")
	contains(command, "--config")

	decodedConfigContent := base64.decode(kubelet_info.data.configFile.content)
	yamlConfig := yaml.unmarshal(decodedConfigContent)
	yamlConfig.rotateCertificates == false

	msga := {
		"alertMessage": "Kubelet client certificates rotation is disabled",
		"alertScore": 6,
		"failedPaths": ["rotateCertificates"],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"externalObjects": {
			"apiVersion": kubelet_info.apiVersion,
			"kind": kubelet_info.kind,
			"data": {"configFile": {"content": decodedConfigContent}},
		}},
	}
}
