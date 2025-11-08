package armo_builtins

import rego.v1

# fails if cni is not enabled like defined in:
# https://learn.microsoft.com/en-us/azure/aks/use-network-policies#create-an-aks-cluster-and-enable-network-policy
deny contains msga if {
	cluster_describe := input[_]
	cluster_describe.apiVersion == "management.azure.com/v1"
	cluster_describe.kind == "ClusterDescribe"
	cluster_describe.metadata.provider == "aks"
	properties := cluster_describe.data.properties

	not cni_enabled_aks(properties)

	msga := {
		"alertMessage": "cni is not enabled",
		"alertScore": 3,
		"packagename": "armo_builtins",
		"failedPaths": [],
		"fixCommand": "",
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [],
			"externalObjects": cluster_describe,
		},
	}
}

cni_enabled_aks(properties) if {
	properties.networkProfile.networkPlugin == "azure"
	properties.networkProfile.networkPolicy == "azure"
}

cni_enabled_aks(properties) if {
	properties.networkProfile.networkPlugin == "azure"
	properties.networkProfile.networkPolicy == "calico"
}

cni_enabled_aks(properties) if {
	properties.networkProfile.networkPlugin == "kubenet"
	properties.networkProfile.networkPolicy == "calico"
}
