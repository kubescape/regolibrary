package armo_builtins

import rego.v1

deny contains msga if {
	cluster_config := input[_]
	cluster_config.apiVersion == "management.azure.com/v1"
	cluster_config.kind == "ClusterDescribe"
	cluster_config.metadata.provider == "aks"
	config := cluster_config.data
	not config.properties.enableRBAC == true

	msga := {
		"alertMessage": "rbac is not enabled",
		"alertScore": 3,
		"packagename": "armo_builtins",
		"reviewPaths": ["data.properties.enableRBAC"],
		"failedPaths": ["data.properties.enableRBAC"],
		"fixCommand": "",
		"fixPaths": [],
		"alertObject": {"externalObjects": cluster_config},
	}
}
