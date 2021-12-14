package armo_builtins
# import data.cautils as cautils
# import data.kubernetes.api.client as client
import data

# fails if config map has keys with suspicious name
deny[msga] {
	configmap := input[_]
    configmap.kind == "ConfigMap"
    sensitive_key_names := data.postureControlInputs.sensitiveKeyNames
    key_name := sensitive_key_names[_]
    map_secret := configmap.data[map_key]
    contains(lower(map_key), lower(key_name))
    path := sprintf("data[%v]", [map_key])
	msga := {
		"alertMessage": sprintf("this configmap has sensitive information: %v", [configmap.metadata.name]),
		"alertScore": 9,
        "failedPaths": [path],
		"packagename": "armo_builtins",
          "alertObject": {
			"k8sApiObjects": [configmap]
		}
     }
}

# fails if config map has values with suspicious content - not base 64
deny[msga] {
    sensitive_values := data.postureControlInputs.sensitiveValues
    value := sensitive_values[_]

	configmap := input[_]
    configmap.kind == "ConfigMap"
    map_secret := configmap.data[map_key]
    regex.match(value , map_secret)
    path := sprintf("data[%v]", [map_key])
	msga := {
		"alertMessage": sprintf("this configmap has sensitive information: %v", [configmap.metadata.name]),
		"alertScore": 9,
        "failedPaths": [path],
		"packagename": "armo_builtins",
          "alertObject": {
			"k8sApiObjects": [configmap]
		}
     }
}

# fails if config map has values with suspicious content - base 64
deny[msga] {
    sensitive_values := data.postureControlInputs.sensitiveValues
    value := sensitive_values[_]

	configmap := input[_]
    configmap.kind == "ConfigMap"
    map_secret := configmap.data[map_key]
    decoded_secret := base64.decode(map_secret)
    regex.match(value , decoded_secret)
    path := sprintf("data[%v]", [map_key])

	msga := {
		"alertMessage": sprintf("this configmap has sensitive information: %v", [configmap.metadata.name]),
		"alertScore": 9,
        "failedPaths": [path],
		"packagename": "armo_builtins",
          "alertObject": {
			"k8sApiObjects": [configmap]
		}
     }
}