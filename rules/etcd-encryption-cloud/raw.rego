package armo_builtins


# Check if encryption in etcd in enabled for EKS
deny[msga] {
	clusterConfig := input[_]
	clusterConfig.kind == "ClusterDescription"
    clusterConfig.group == "cloudvendordata.armo.cloud"	
    clusterConfig.provider == "eks"

	isNotEncrypted(clusterConfig)
    
	
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


isNotEncrypted(clusterConfig) {
	encryptionConfig := clusterConfig.cluster.encryptionConfig[_]
    goodResources := [resource  | resource =   encryptionConfig.resources[_]; resource == "secrets"]
	count(goodResources) > 0
}

isNotEncrypted(clusterConfig) {
	clusterConfig.cluster.encryptionConfig == null
}

isNotEncrypted(clusterConfig) {
	count(clusterConfig.cluster.encryptionConfig) == 0
}

isNotEncrypted(clusterConfig) {
	encryptionConfig := clusterConfig.cluster.encryptionConfig[_]
    count(encryptionConfig.resources) == 0
}