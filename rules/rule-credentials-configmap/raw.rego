package armo_builtins
# import data.cautils as cautils
# import data.kubernetes.api.client as client
import data

# fails if config map has keys with suspicious name
deny[msga] {
	configmap := input[_]
    configmap.kind == "ConfigMap"
   
    map_secret := configmap.data[map_key]
    map_secret != ""
    is_sensitive_key_name(map_key)

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
	configmap := input[_]
    configmap.kind == "ConfigMap"

    map_secret := configmap.data[map_key]
    map_secret != ""
    is_sensitive_key_value(map_secret)

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
	configmap := input[_]
    configmap.kind == "ConfigMap"

    map_secret := configmap.data[map_key]
    map_secret != ""
    decoded_secret := base64.decode(map_secret)
    is_sensitive_key_value(decoded_secret)
    
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


# see default-config-inputs.json for list values

## For key names
is_sensitive_key_name(map_key)
{
    sensitive_key_name := data.postureControlInputs.sensitiveKeyNames[_]
    contains(lower(map_key), lower(sensitive_key_name))
    # check that sensitive key name is not on allowlist
    data.postureControlInputs.sensitiveKeyNamesAllowlist
	sensitive_key_names_allowed_list := [sensitive_key_names_allowed |  sensitive_key_names_allowed= data.postureControlInputs.sensitiveKeyNamesAllowlist[_]; contains(lower(map_key), lower(sensitive_key_names_allowed))]
	count(sensitive_key_names_allowed_list) == 0
}

is_sensitive_key_name(map_key)
{
    sensitive_key_name := data.postureControlInputs.sensitiveKeyNames[_]
    contains(lower(map_key), lower(sensitive_key_name))
    not data.postureControlInputs.sensitiveKeyNamesAllowlist
}


## For key values
is_sensitive_key_value(map_secret)
{
    sensitive_value := data.postureControlInputs.sensitiveValues[_]
    regex.match(sensitive_value , map_secret)
    data.postureControlInputs.sensitiveValuesAllowlist
	sensitive_values_allowed_list := [sensitive_value_allowed |  sensitive_value_allowed = data.postureControlInputs.sensitiveValuesAllowlist[_];  regex.match(sensitive_value_allowed , map_secret)]
	count(sensitive_values_allowed_list) == 0
}

is_sensitive_key_value(map_secret)
{
    sensitive_value := data.postureControlInputs.sensitiveValues[_]
    regex.match(sensitive_value , map_secret)
    not data.postureControlInputs.sensitiveValuesAllowlist
}