package armo_builtins

deny[msga] {
	kubelet_info := input[_]
	kubelet_info.kind == "KubeletInfo"
	kubelet_info.apiVersion == "hostdata.kubescape.cloud/v1beta0"

	command := kubelet_info.data.cmdLine

	not contains(command, "--tls-cert-file")
	not contains(command, "--tls-private-key-file")
	not contains(command, "--config")
	
	external_obj := json.filter(kubelet_info, ["apiVersion", "data/cmdLine", "kind"])

	msga := {
		"alertMessage": "kubelet client TLS authentication is not enabled",
		"alertScore": 2,
		"fixPaths": [],
		"failedPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"externalObjects": external_obj},
	}
}

deny[msga] {
	kubelet_info := input[_]
	kubelet_info.kind == "KubeletInfo"
	kubelet_info.apiVersion == "hostdata.kubescape.cloud/v1beta0"
	command := kubelet_info.data.cmdLine

	not contains(command, "--tls-cert-file")
	not contains(command, "--tls-private-key-file")
	contains(command, "--config")

	decodedConfigContent := base64.decode(kubelet_info.data.configFile.content)
	yamlConfig := yaml.unmarshal(decodedConfigContent)

	not yamlConfig.tlsCertFile
	not yamlConfig.tlsPrivateKeyFile

	msga := {
		"alertMessage": "tlsCertFile and tlsPrivateKeyFile are not set",
		"alertScore": 2,
		"failedPaths": [],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"externalObjects": {
			"apiVersion": kubelet_info.apiVersion,
			"kind": kubelet_info.kind,
			"data": {"configFile": {"content": decodedConfigContent}},
		}}
	}
}
