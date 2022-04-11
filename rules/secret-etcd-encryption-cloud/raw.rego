package armo_builtins


# Check if encryption in etcd in enabled for EKS
deny[msga] {
	clusterConfig := input[_]
	clusterConfig.apiVersion == "eks.amazonaws.com/v1"
	clusterConfig.kind == "ClusterDescribe"
    clusterConfig.metadata.provider == "eks"	
	config = clusterConfig.data

	isNotEncryptedEKS(config)
    
	
	msga := {
		"alertMessage": "etcd/secret encryption is not enabled",
		"alertScore": 3,
		"packagename": "armo_builtins",
		"failedPaths": [],
		"fixPaths": [],
		"fixCommand": "eksctl utils enable-secrets-encryption --cluster=<cluster> --key-arn=arn:aws:kms:<cluster_region>:<account>:key/<key> --region=<region>",
		"alertObject": {
			"k8sApiObjects": [],
            "externalObjects": clusterConfig
		}
	}
}



# Check if encryption in etcd in enabled for GKE
deny[msga] {
	clusterConfig := input[_]
	clusterConfig.apiVersion == "container.googleapis.com/v1"
	clusterConfig.kind == "ClusterDescribe"
    clusterConfig.metadata.provider == "gke"	
	config := clusterConfig.data

	not isEncryptedGKE(config)
    
	
	msga := {
		"alertMessage": "etcd/secret encryption is not enabled",
		"alertScore": 3,
		"packagename": "armo_builtins",
		"failedPaths": ["data.database_encryption.state"],
		"fixPaths": [],
		"fixCommand": "gcloud container clusters update <cluster_name> --region=<compute_region> --database-encryption-key=<key_project_id>/locations/<location>/keyRings/<ring_name>/cryptoKeys/<key_name> --project=<cluster_project_id>",
		"alertObject": {
			"k8sApiObjects": [],
            "externalObjects": clusterConfig
		}
	}
}

isEncryptedGKE(config) {
	 config.database_encryption.state == "1"
}
isEncryptedGKE(config) {
	 config.database_encryption.state == "ENCRYPTED"
}

isNotEncryptedEKS(clusterConfig) {
	encryptionConfig := clusterConfig.Cluster.EncryptionConfig[_]
    goodResources := [resource  | resource =   clusterConfig.Cluster.EncryptionConfig.Resources[_]; resource == "secrets"]
	count(goodResources) == 0
}

isNotEncryptedEKS(clusterConfig) {
	clusterConfig.Cluster.EncryptionConfig == null
}

isNotEncryptedEKS(clusterConfig) {
	count(clusterConfig.Cluster.EncryptionConfig) == 0
}

isNotEncryptedEKS(clusterConfig) {
	encryptionConfig := clusterConfig.Cluster.EncryptionConfig[_]
    count(encryptionConfig.Resources) == 0
}