package armo_builtins

import rego.v1

# Checks if Ingress is connected to a service and a workload to expose something
deny contains msga if {
	pv := input[_]
	pv.kind == "PersistentVolume"

	# Find the related storage class
	storageclass := input[_]
	storageclass.kind == "StorageClass"
	pv.spec.storageClassName == storageclass.metadata.name

	# Check if storage class is encrypted
	not is_storage_class_encrypted(storageclass)

	msga := {
		"alertMessage": sprintf("Volume '%v' has is using a storage class that does not use encryption", [pv.metadata.name]),
		"packagename": "armo_builtins",
		"failedPaths": [],
		"fixPaths": [{
			"path": "spec.storageClassName",
			"value": "<your encrypted storage class>",
		}],
		"alertScore": 7,
		"alertObject": {"k8sApiObjects": [pv]},
	}
}

# Storage class is encrypted - AWS
is_storage_class_encrypted(storageclass) if {
	storageclass.parameters.encrypted == "true"
}

# Storage class is encrypted - Azure
is_storage_class_encrypted(storageclass) if {
	storageclass.provisioner
	contains(storageclass.provisioner, "azure")
}

# Storage class is encrypted - GCP
is_storage_class_encrypted(storageclass) if {
	# GKE encryption is enabled by default https://cloud.google.com/blog/products/containers-kubernetes/exploring-container-security-use-your-own-keys-to-protect-your-data-on-gke
	storageclass.provisioner
	contains(storageclass.provisioner, "csi.storage.gke.io")
}
