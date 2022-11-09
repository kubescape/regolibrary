package armo_builtins

import future.keywords.every

# Encryption config is not using a recommended provider for KMS
deny[msg] {
	obj = input[_]
	is_control_plane_info(obj)
	config_file := obj.data.APIServerInfo.encryptionProviderConfigFile
	config_file_content = decode_config_file(base64.decode(config_file.content))

	resources := config_file_content.resources
	resource := resources[_]
	every resource in resources{
		not has_recommended_provider(resource)
	}

	fix_paths := [
	{"path": sprintf("resources[%d].resources[%d]", [count(resources), 0]),	"value": "secrets"},
	{"path": sprintf("resources[%d].providers[%d].kms", [count(resources), 0]),	"value": "YOUR_EXTERNAL_KMS"},
	]

	# Add name to the failed object so that
	# it fit the format of the alert object
	failed_obj := json.patch(config_file_content, [{
		"op": "add",
		"path": "name",
		"value": "encryption-provider-config",
	}])

	msg := {
		"alertMessage": "Encryption provider config is not using a recommended provider for KMS",
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

has_recommended_provider(resource) {
	recommended_providers := {"akeyless", "azurekmsprovider", "aws-encryption-provider"}
	some provider in resource.providers
	recommended_providers[provider.kms.name]
}
