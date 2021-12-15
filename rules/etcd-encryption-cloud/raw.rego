package armo_builtins


# Check if encryption in etcd in enabled for EKS
deny[msga] {
	clusterConfig := input[_]
	clusterConfig.kind == "ClusterDescription"
    clusterConfig.group == "cloudvendordata.armo.cloud"	
    clusterConfig.provider == "eks"

	count(clusterConfig.cluster.encryptionConfig) > 0
    encryptionConfig := clusterConfig.cluster.encryptionConfig[_]
	count(encryptionConfig.resources) > 0
    resource := encryptionConfig.resources[_]
    resource == "secrets"
	
	msga := {
		"alertMessage": "etcd encryption is not enabled",
		"alertScore": 9,
		"packagename": "armo_builtins",
		"failedPaths":[] ,
		"alertObject": {
			"k8sApiObjects": [],
            "externalObjects": clusterConfig
		}
	}
}



# Check if encryption in etcd in enabled for GKE
deny[msga] {
	clusterConfig := input[_]
	clusterConfig.kind == "ClusterDescription"
    clusterConfig.group == "cloudvendordata.armo.cloud"
    clusterConfig.provider == "gke"
    not clusterConfig.databaseEncryption.state == "ENCRYPTED"
	
	msga := {
		"alertMessage": "etcd encryption is not enabled",
		"alertScore": 9,
		"packagename": "armo_builtins",
		"failedPaths": [],
		"alertObject": {
			"k8sApiObjects": [],
            "externalObjects": clusterConfig
		}
	}
}