package armo_builtins
# import data.cautils as cautils
# import data.kubernetes.api.client as client

# fails if config map has keys with suspicious name
deny[msga] {
	configmap := input[_]
    configmap.kind == "ConfigMap"
    sensitive_key_names := {"aws_access_key_id", "aws_secret_access_key", "azure_batchai_storage_account", "azure_batchai_storage_key",
                            "azure_batch_account", "azure_batch_key", "pass", "username", "pwd", "cred", "token", "key", "cert"}
    key_name := sensitive_key_names[_]
    map_secret := configmap.data[map_key]
    contains(lower(map_key), key_name)
	msga := {
		"alertMessage": sprintf("this configmap has sensitive information: %v", [configmap.metadata.name]),
		"alertScore": 9,
		"packagename": "armo_builtins",
          "alertObject": {
			"k8sApiObjects": [configmap]
		}
     }
}

# fails if config map has values with suspicious content - not base 64
deny[msga] {
    sensitive_values := {"BEGIN", "PRIVATE KEY", "eyJhbGciO"}
    value := sensitive_values[_]

	configmap := input[_]
    configmap.kind == "ConfigMap"
    map_secret := configmap.data[map_key]
    contains(map_secret, value)

	msga := {
		"alertMessage": sprintf("this configmap has sensitive information: %v", [configmap.metadata.name]),
		"alertScore": 9,
		"packagename": "armo_builtins",
          "alertObject": {
			"k8sApiObjects": [configmap]
		}
     }
}

# fails if config map has values with suspicious content - base 64
deny[msga] {
    sensitive_values := {"BEGIN", "PRIVATE KEY", "eyJhbGciO"}
    value := sensitive_values[_]

	configmap := input[_]
    configmap.kind == "ConfigMap"
    map_secret := configmap.data[map_key]
    decoded_secret := base64.decode(map_secret)
    contains(decoded_secret, value)

	msga := {
		"alertMessage": sprintf("this configmap has sensitive information: %v", [configmap.metadata.name]),
		"alertScore": 9,
		"packagename": "armo_builtins",
          "alertObject": {
			"k8sApiObjects": [configmap]
		}
     }
}