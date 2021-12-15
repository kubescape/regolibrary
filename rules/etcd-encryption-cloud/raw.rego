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
	encryptionConfig := clusterConfig.Cluster.EncryptionConfig[_]
    goodResources := [resource  | resource =   clusterConfig.Cluster.EncryptionConfig.Resources[_]; resource == "secrets"]
	count(goodResources) == 0
}

isNotEncrypted(clusterConfig) {
	clusterConfig.Cluster.EncryptionConfig == null
}

isNotEncrypted(clusterConfig) {
	count(clusterConfig.Cluster.EncryptionConfig) == 0
}

isNotEncrypted(clusterConfig) {
	encryptionConfig := clusterConfig.Cluster.EncryptionConfig[_]
    count(encryptionConfig.Resources) == 0
}