# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

# CIS 4.2.1 https://workbench.cisecurity.org/sections/1126668/recommendations/1838638

deny contains msga if {
	obj := input[_]
	is_kubelet_info(obj)
	command := obj.data.cmdLine

	anonymous_auth_flag_enabled(command)

	external_obj := json.filter(obj, ["apiVersion", "data/cmdLine", "kind", "metadata"])

	msga := {
		"alertMessage": "Anonymous requests is enabled.",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"externalObjects": external_obj},
	}
}

deny contains msga if {
	obj := input[_]
	is_kubelet_info(obj)
	command := obj.data.cmdLine

	not contains(command, "--anonymous-auth")
	contains(command, "--config")

	decodedConfigContent := base64.decode(obj.data.configFile.content)
	yamlConfig := yaml.unmarshal(decodedConfigContent)
	yamlConfig.authentication.anonymous.enabled == true

	msga := {
		"alertMessage": "Anonymous requests is enabled.",
		"alertScore": 7,
		"reviewPaths": ["authentication.anonymous.enabled"],
		"failedPaths": ["authentication.anonymous.enabled"],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"externalObjects": {
			"apiVersion": obj.apiVersion,
			"kind": obj.kind,
			"metadata": obj.metadata,
			"data": {"configFile": {"content": decodedConfigContent}},
		}},
	}
}

## Host sensor failed to get config file content
deny contains msga if {
	obj := input[_]
	is_kubelet_info(obj)

	command := obj.data.cmdLine

	not contains(command, "--anonymous-auth")
	contains(command, "--config")

	not obj.data.configFile.content

	msga := {
		"alertMessage": "Failed to analyze config file",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"externalObjects": {
			"apiVersion": obj.apiVersion,
			"kind": obj.kind,
			"metadata": obj.metadata,
			"data": obj.data,
		}},
	}
}

anonymous_auth_flag_enabled(command) if contains(command, "--anonymous-auth=true")

# A bare boolean flag means true.
anonymous_auth_flag_enabled(command) if regex.match(`(^|[[:space:]])--anonymous-auth([[:space:]]|$)`, command)

is_kubelet_info(obj) if {
	obj.kind == "KubeletInfo"
	obj.apiVersion == "hostdata.kubescape.cloud/v1beta0"
}
