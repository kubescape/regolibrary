package armo_builtins

# fails in case Azure RBAC is not set on AKS instance.
deny[msga] {
   	cluster_describe := input[_]
	cluster_describe.apiVersion == "management.azure.com/v1"
	cluster_describe.kind == "ClusterDescribe"
	cluster_describe.metadata.provider == "aks"
	properties := cluster_describe.data.properties

	not isAzureRBACEnabled(properties)

	msga := {
		"alertMessage": "Azure RBAC is not set. Enable it using the command: az aks update -g <resource_group> -n <cluster_name> --enable-azure-rbac",
		"alertScore": 7,
		"packagename": "armo_builtins",
		"failedPaths": [],
		"fixCommand": "az aks update -g <resource_group> -n <cluster_name> --enable-azure-rbac",
		"fixPaths": [],
		"alertObject": {
			"externalObjects": cluster_describe
		},
	} 
}

# isAzureRBACEnabled check if Azure RBAC is enabled into ClusterDescribe object
# retrieved from azure cli.
isAzureRBACEnabled(properties) {
    properties.aadProfile.enableAzureRBAC == true
}
