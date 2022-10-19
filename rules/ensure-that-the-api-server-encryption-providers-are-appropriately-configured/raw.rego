package armo_builtins

import future.keywords.in

# Encryption config is set but not using one of the recommended providers
deny[msg] {
	obj = input[_]
	is_control_plane_info(obj)
	config_file := obj.data.APIServerInfo.encryptionProviderConfigFile
	config_file_content = decode_config_file(base64.decode(config_file.content))

	# For each resource check if it does not have allowed provider
	fix_paths := [{
		"path": sprintf("resources[%d].providers[%d]", [i, count(resource.providers)]),
		"value": "{\"aescbc\" | \"secretbox\" | \"kms\" : <provider config>}", # must be string
	} |
		resource := config_file_content.resources[i]
		count({true |
			some provider in resource.providers
			has_one_of_keys(provider, ["aescbc", "secretbox", "kms"])
		}) == 0
	]

	count(fix_paths) > 0

	# Add name to the failed object so that
	# it fit the format of the alert object
	failed_obj := json.patch(config_file_content, [{
		"op": "add",
		"path": "name",
		"value": "encryption-provider-config",
	}])

	msg := {
		"alertMessage": "Encryption provider config is not using one of the allowed providers (aescbc, secretbox, kms)",
		"alertScore": 2,
		"failedPaths": [],
		"fixPaths": fix_paths,
		"packagename": "armo_builtins",
		"alertObject": {"externalObjects": failed_obj},
	}
}

is_control_plane_info(obj) {
	obj.apiVersion == "hostdata.kubescape.cloud/v1beta0"
	obj.kind == "ControlPlaneInfo"
}

decode_config_file(content) := data {
	data := yaml.unmarshal(content)
} else := json.unmarshal(content)

has_key(x, k) {
	_ = x[k]
}

has_one_of_keys(x, keys) {
	has_key(x, keys[_])
}
