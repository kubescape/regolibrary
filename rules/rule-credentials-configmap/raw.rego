package armo_builtins
# import data.cautils as cautils
# import data.kubernetes.api.client as client
import data

# fails if config map has keys with suspicious name
deny[msga] {
	configmap := input[_]
    configmap.kind == "ConfigMap"
    # see default-config-inputs.json for list values
    sensitive_key_names := data.postureControlInputs.sensitiveKeyNames
    key_name := sensitive_key_names[_]
    map_secret := configmap.data[map_key]
    map_secret != ""
    
    contains(lower(map_key), lower(key_name))
    # check that value wasn't allowed by user
    not is_allowed_value(map_secret)
    
    path := sprintf("data[%v]", [map_key])

	msga := {
		"alertMessage": sprintf("this configmap has sensitive information: %v", [configmap.metadata.name]),
		"alertScore": 9,
        "failedPaths": [path],
        "fixPaths": [],
		"packagename": "armo_builtins",
          "alertObject": {
			"k8sApiObjects": [configmap]
		}
     }
}

# fails if config map has values with suspicious content - not base 64
deny[msga] {
    # see default-config-inputs.json for list values
    sensitive_values := data.postureControlInputs.sensitiveValues
    value := sensitive_values[_]

	configmap := input[_]
    configmap.kind == "ConfigMap"
    map_secret := configmap.data[map_key]
    map_secret != ""

    regex.match(value , map_secret)
    # check that value wasn't allowed by user
    not is_allowed_value(map_secret)

    path := sprintf("data[%v]", [map_key])

	msga := {
		"alertMessage": sprintf("this configmap has sensitive information: %v", [configmap.metadata.name]),
		"alertScore": 9,
        "failedPaths": [path],
        "fixPaths": [],
		"packagename": "armo_builtins",
          "alertObject": {
			"k8sApiObjects": [configmap]
		}
     }
}

# fails if config map has values with suspicious content - base 64
deny[msga] {
    # see default-config-inputs.json for list values
    sensitive_values := data.postureControlInputs.sensitiveValues
    value := sensitive_values[_]

	configmap := input[_]
    configmap.kind == "ConfigMap"
    map_secret := configmap.data[map_key]
    map_secret != ""

    decoded_secret := base64.decode(map_secret)
    
    # check that value wasn't allowed by user
    not is_allowed_value(map_secret)

    regex.match(value , decoded_secret)

    path := sprintf("data[%v]", [map_key])

	msga := {
		"alertMessage": sprintf("this configmap has sensitive information: %v", [configmap.metadata.name]),
		"alertScore": 9,
        "failedPaths": [path],
        "fixPaths": [],
		"packagename": "armo_builtins",
          "alertObject": {
			"k8sApiObjects": [configmap]
		}
     }
}


is_allowed_value(value) {
    allow_val := data.postureControlInputs.sensitiveValuesAllowed[_]
    value == allow_val
}