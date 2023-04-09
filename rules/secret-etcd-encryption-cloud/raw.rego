package armo_builtins

# Check if encryption in etcd in enabled for AKS
deny[msga] {
	cluster_config := input[_]
	cluster_config.apiVersion == "management.azure.com/v1"
	cluster_config.kind == "ClusterDescribe"
    cluster_config.metadata.provider == "aks"	
	config = cluster_config.data

	not isEncryptedAKS(config)
	
	msga := {
		"alertMessage": "etcd/secret encryption is not enabled",
		"alertScore": 3,
		"packagename": "armo_builtins",
		"failedPaths": [],
		"fixPaths": [],
		"fixCommand": "az aks nodepool add --name hostencrypt --cluster-name <myAKSCluster> --resource-group <myResourceGroup> -s Standard_DS2_v2 -l <myRegion> --enable-encryption-at-host",
		"alertObject": {
            "externalObjects": cluster_config
		}
	}
}


# Check if encryption in etcd in enabled for EKS
deny[msga] {
	cluster_config := input[_]
	cluster_config.apiVersion == "eks.amazonaws.com/v1"
	cluster_config.kind == "ClusterDescribe"
    cluster_config.metadata.provider == "eks"	
	config = cluster_config.data

	is_not_encrypted_EKS(config)
    
	
	msga := {
		"alertMessage": "etcd/secret encryption is not enabled",
		"alertScore": 3,
		"packagename": "armo_builtins",
		"failedPaths": [],
		"fixPaths": [],
		"fixCommand": "eksctl utils enable-secrets-encryption --cluster=<cluster> --key-arn=arn:aws:kms:<cluster_region>:<account>:key/<key> --region=<region>",
		"alertObject": {
			"k8sApiObjects": [],
            "externalObjects": cluster_config
		}
	}
}



# Check if encryption in etcd in enabled for GKE
deny[msga] {
	cluster_config := input[_]
	cluster_config.apiVersion == "container.googleapis.com/v1"
	cluster_config.kind == "ClusterDescribe"
    cluster_config.metadata.provider == "gke"	
	config := cluster_config.data

	not is_encrypted_GKE(config)
    
	
	msga := {
		"alertMessage": "etcd/secret encryption is not enabled",
		"alertScore": 3,
		"packagename": "armo_builtins",
		"failedPaths": ["data.database_encryption.state"],
		"fixPaths": [],
		"fixCommand": "gcloud container clusters update <cluster_name> --region=<compute_region> --database-encryption-key=<key_project_id>/locations/<location>/keyRings/<ring_name>/cryptoKeys/<key_name> --project=<cluster_project_id>",
		"alertObject": {
			"k8sApiObjects": [],
            "externalObjects": cluster_config
		}
	}
}

is_encrypted_GKE(config) {
	 config.database_encryption.state == "1"
}
is_encrypted_GKE(config) {
	 config.database_encryption.state == "ENCRYPTED"
}

is_not_encrypted_EKS(cluster_config) {
	encryptionConfig := cluster_config.Cluster.EncryptionConfig[_]
    goodResources := [resource  | resource =   cluster_config.Cluster.EncryptionConfig.Resources[_]; resource == "secrets"]
	count(goodResources) == 0
}

is_not_encrypted_EKS(cluster_config) {
	cluster_config.Cluster.EncryptionConfig == null
}

is_not_encrypted_EKS(cluster_config) {
	count(cluster_config.Cluster.EncryptionConfig) == 0
}

is_not_encrypted_EKS(cluster_config) {
	encryptionConfig := cluster_config.Cluster.EncryptionConfig[_]
    count(encryptionConfig.Resources) == 0
}

isEncryptedAKS(cluster_config) {
	cluster_config.properties.agentPoolProfiles.enableEncryptionAtHost == true
}
