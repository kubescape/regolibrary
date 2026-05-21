package armo_builtins

import rego.v1

# check if the EKS cluster is configured with the Cluster Access Manager API
# by checking in the ClusterDescribe resource if accessConfig.AuthenticationMode is set to 'CONFIG_MAP'
# If "authenticationmode": "API" or "authenticationmode": "API_AND_CONFIG_MAP", it means the Cluster Access Manager API is enabled.
deny contains msga if {
	cluster_config := input[_]
	cluster_config.apiVersion == "eks.amazonaws.com/v1"
	cluster_config.kind == "ClusterDescribe"
	cluster_config.metadata.provider == "eks"
	config := cluster_config.data

	config.Cluster.AccessConfig.AuthenticationMode == "CONFIG_MAP"

	msga := {
		"alertMessage": "Cluster Access Manager API isn't enabled on the EKS cluster",
		"alertScore": 3,
		"packagename": "armo_builtins",
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [],
			"externalObjects": cluster_config,
		},
	}
}
