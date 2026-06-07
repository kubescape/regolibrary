# regal ignore:directory-package-mismatch  
package armo_builtins

import rego.v1

# Check if encryption in etcd in enabled for AKS
deny contains msga if {
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
		"alertObject": {"externalObjects": cluster_config},
	}
}

# Check if encryption in etcd is enabled for EKS
deny contains msga if {
	cluster_config := input[_]
	cluster_config.apiVersion == "eks.amazonaws.com/v1"
	cluster_config.kind == "ClusterDescribe"
	cluster_config.metadata.provider == "eks"
	config := cluster_config.data

	not is_encrypted_EKS(config)

	msga := {
		"alertMessage": "etcd/secret encryption is not enabled",
		"alertScore": 3,
		"packagename": "armo_builtins",
		"failedPaths": [],
		"fixPaths": [],
		"fixCommand": "eksctl utils enable-secrets-encryption --cluster=<cluster> --key-arn=arn:aws:kms:<cluster_region>:<account>:key/<key> --region=<region>",
		"alertObject": {
			"k8sApiObjects": [],
			"externalObjects": cluster_config,
		},
	}
}

# Check if encryption in etcd in enabled for GKE
deny contains msga if {
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
		"reviewPaths": ["data.database_encryption.state"],
		"failedPaths": ["data.database_encryption.state"],
		"fixPaths": [],
		"fixCommand": "gcloud container clusters update <cluster_name> --region=<compute_region> --database-encryption-key=<key_project_id>/locations/<location>/keyRings/<ring_name>/cryptoKeys/<key_name> --project=<cluster_project_id>",
		"alertObject": {
			"k8sApiObjects": [],
			"externalObjects": cluster_config,
		},
	}
}

is_encrypted_GKE(config) if {
	config.database_encryption.state == "1"
}

is_encrypted_GKE(config) if {
	config.database_encryption.state == "ENCRYPTED"
}

is_encrypted_EKS(config) if {
	encryption := config.Cluster.EncryptionConfig[_]
	encryption.Provider.KeyArn != ""
	count(encryption.Resources) > 0
}

# Accept the camelCase shape too. kubescape's cloud collector normally
# feeds this rule the aws-sdk-go v2 DescribeClusterOutput struct which
# marshals to PascalCase (Cluster.EncryptionConfig). Environments that
# hand the raw AWS CLI / describe-cluster JSON (cluster.encryptionConfig)
# would otherwise always trip the C-0066 deny even with KMS actually
# enabled (kubescape/kubescape#1959).
is_encrypted_EKS(config) if {
	encryption := config.cluster.encryptionConfig[_]
	encryption.provider.keyArn != ""
	count(encryption.resources) > 0
}

isEncryptedAKS(cluster_config) if {
	profiles := cluster_config.properties.agentPoolProfiles
	count(profiles) > 0
	every p in profiles { p.enableEncryptionAtHost == true }
}

isEncryptedAKS(cluster_config) if {
	cluster_config.properties.securityProfile.azureKeyVaultKms.enabled == true
}

isEncryptedAKS(cluster_config) if {
	cluster_config.properties.securityProfile.kubernetesResourceObjectEncryptionProfile.infrastructureEncryption == "Enabled"
}
