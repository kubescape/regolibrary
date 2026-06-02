package armo_builtins

import rego.v1

# fails in case enablePrivateCluster is set to false.
deny contains msga if {
	obj := input[_]
	obj.apiVersion == "management.azure.com/v1"
	obj.kind == "ClusterDescribe"
	obj.metadata.provider == "aks"
	config = obj.data

	not isPrivateClusterEnabled(config)

	msga := {
		"alertMessage": "Cluster does not have private nodes.",
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [],
		"fixCommand": "az aks create --resource-group <private-cluster-resource-group> --name <private-cluster-name> --load-balancer-sku standard --enable-private-cluster --network-plugin azure --vnet-subnet-id <subnet-id> --docker-bridge-address --dns-service-ip --service-cidr",
		"alertObject": {"externalObjects": obj},
	}
}

isPrivateClusterEnabled(config) if {
	config.properties.apiServerAccessProfile.enablePrivateCluster == true
}
