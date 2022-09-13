package armo_builtins

# --client-ca-file argument not present in CLI
deny[msga] {
	kubelet_info := input[_]
	kubelet_info.kind == "KubeletInfo"
	kubelet_info.apiVersion == "hostdata.kubescape.cloud/v1beta0"
	command := kubelet_info.data.cmdLine

	not contains(command, "--client-ca-file")
	contains(command, "--config")

	decodedConfigContent := base64.decode(kubelet_info.data.configFile.content)
	yamlConfig := yaml.unmarshal(decodedConfigContent)
	not yamlConfig.authentication.x509.clientCAFile

	msga := {
		"alertMessage": "kubelet client TLS authentication is not enabled",
		"alertScore": 6,
		"failedPaths": ["authentication.x509.clientCAFile"],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"externalObjects": {
			"apiVersion": kubelet_info.apiVersion,
			"kind": kubelet_info.kind,
			"data": {"configFile": {"content": decodedConfigContent}},
		}},
	}
}
