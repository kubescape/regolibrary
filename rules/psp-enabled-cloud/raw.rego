package armo_builtins


# Check if PSP is enabled for GKE
deny[msga] {
	clusterConfig := input[_]
	clusterConfig.kind == "Description"
    clusterConfig.group == "CloudProviderData"
    clusterConfig.provider == "gke"
    clusterConfig.podSecurityPolicyConfig.enabled == "true"
	
	msga := {
		"alertMessage": sprintf("etcd encryption is not enabled"),
		"alertScore": 9,
		"packagename": "armo_builtins",
		"failedPaths": [],
		"alertObject": {
			"k8sApiObjects": [],
			"externalObjects": 
		}
	}
}

# TODO - EKS. By default has a policy which allows everything