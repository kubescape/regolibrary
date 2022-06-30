package armo_builtins


deny[msga] {
	cluster_config := input[_]
	cluster_config.apiVersion == "management.azure.com/v1"
	cluster_config.kind == "ClusterDescribe"
    cluster_config.metadata.provider == "aks"	
    config := cluster_config.data
    config.properties.enableRBAC == false

	msga := {
		"alertMessage": "rbac is not enabled",
		"alertScore": 3,
		"packagename": "armo_builtins",
		"failedPaths": ["data.properties.enableRBAC"],
		"fixCommand": "",
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [],
            "externalObjects": cluster_config
		}
	}
}

