package armo_builtins

#CIS 4.2.10 https://workbench.cisecurity.org/sections/1126668/recommendations/1838657

deny[msga] {
	obj := input[_]
	is_kubelet_info(obj)

	command := obj.data.cmdLine

	not contains(command, "--tls-cert-file")
	not contains(command, "--tls-private-key-file")
	not contains(command, "--config")

	external_obj := json.filter(obj, ["apiVersion", "data/cmdLine", "kind"])

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
	obj := input[_]
	is_kubelet_info(obj)

	command := obj.data.cmdLine

	not contains(command, "--tls-cert-file")
	not contains(command, "--tls-private-key-file")
	contains(command, "--config")

	decodedConfigContent := base64.decode(obj.data.configFile.content)
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
			"apiVersion": obj.apiVersion,
			"kind": obj.kind,
			"data": {"configFile": {"content": decodedConfigContent}},
		}},
	}
}

is_kubelet_info(obj) {
	obj.kind == "KubeletInfo"
	obj.apiVersion == "hostdata.kubescape.cloud/v1beta0"
}

is_one_arg_not_set(cmd) {
	wanted := ["--tls-cert-file", "--tls-private-key-file"]
	fix_paths = [ |
		not contains(full_cmd, wanted[i][0])
	]
	count(contains(cmd, wanted[i])) != 2
}
