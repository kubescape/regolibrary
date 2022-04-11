package armo_builtins


# Check if PSP is enabled for GKE
deny[msga] {
	clusterConfig := input[_]
	clusterConfig.apiVersion == "container.googleapis.com/v1"
	clusterConfig.kind == "ClusterDescribe"
    clusterConfig.metadata.provider == "gke"	
	config := clusterConfig.data
    not config.pod_security_policy_config.enabled == true

	
	msga := {
		"alertMessage": "pod security policy configuration is not enabled",
		"alertScore": 3,
		"packagename": "armo_builtins",
		"failedPaths": [],
		"fixPaths": [],
		"fixCommand": "gcloud beta container clusters update <cluster_name> --enable-pod-security-policy",
		"alertObject": {
			"k8sApiObjects": [],
            "externalObjects": clusterConfig
		}
	}
}