package armo_builtins


deny[msga] {
	clusterConfig := input[_]
	clusterConfig.apiVersion == "management.azure.com/v1"
	clusterConfig.kind == "ClusterDescribe"
    clusterConfig.metadata.provider == "aks"	
    config := clusterConfig.data
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
            "externalObjects": clusterConfig
		}
	}
}

