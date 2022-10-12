package armo_builtins

import future.keywords.in

# Encryption config is not set at all 
deny[msg] {
	obj = input[_]
	is_api_server(obj)

	cmd := obj.spec.containers[0].command
	not contains(concat(" ", cmd), "--encryption-provider-config")

	msg := {
		"alertMessage": "Encryption provider config file not set",
		"alertScore": 2,
		"failedPaths": [],
		"fixPaths": [{
			"path": sprintf("spec.containers[0].command[%d]", [count(cmd)]),
			"value": "--encryption-provider-config=<path/to/encryption-config.yaml>",
		}],
		"packagename": "armo_builtins",
		"alertObject": {"k8sApiObjects": [obj]},
	}
}

# Encryption config is set but not covering secrets
deny[msg] {
	obj = input[_]
	is_control_plane_info(obj)
	config_file := obj.data.APIServerInfo.encryptionProviderConfigFile
	config_file_content = decode_config_file(base64.decode(config_file.content))

	# Check if the config conver secrets
	count({true | "secrets" in config_file_content.resources[_].resources}) == 0
	
	# Add name to the failed object so that
	# it fit the format of the alert object
	failed_obj := json.patch(config_file_content, [{
		"op": "add",
		"path": "name",
		"value": "encryption-provider-config",
	}])

	msg := {
		"alertMessage": "Encryption provider config is not covering secrets",
		"alertScore": 2,
		"failedPaths": [],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"externalObjects": failed_obj},
	}
}

is_api_server(obj) {
	obj.apiVersion == "v1"
	obj.kind == "Pod"
	obj.metadata.namespace == "kube-system"
	count(obj.spec.containers) == 1
	count(obj.spec.containers[0].command) > 0
	endswith(obj.spec.containers[0].command[0], "kube-apiserver")
}

is_control_plane_info(obj) {
	obj.apiVersion == "hostdata.kubescape.cloud/v1beta0"
	obj.kind == "ControlPlaneInfo"
}

decode_config_file(content) := data {
	data := yaml.unmarshal(content)
} else := json.unmarshal(content)
