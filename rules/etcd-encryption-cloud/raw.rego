package armo_builtins


# Check if encryption in etcd in enabled for EKS
deny[msga] {
	clusterConfig := input[_]
	clusterConfig.kind == "Description"
    clusterConfig.group == "CloudProviderData"
    clusterConfig.provider == "eks"

    encryptionConfig := clusterConfig.cluster.encryptionConfig[_]
    resource := encryptionConfig.resources[_]
    resource == "secrets"
	
	msga := {
		"alertMessage": sprintf("etcd encryption is not enabled"),
		"alertScore": 9,
		"packagename": "armo_builtins",
		"failedPaths": ,
		"alertObject": {
			"k8sApiObjects": [],
			"externalObjects": 
		}
	}
}



# Check if encryption in etcd in enabled for GKE
deny[msga] {
	clusterConfig := input[_]
	clusterConfig.kind == "Description"
    clusterConfig.group == "CloudProviderData"
    clusterConfig.provider == "gke"
    clusterConfig.databaseEncryption.state == "ENCRYPTED"
	
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