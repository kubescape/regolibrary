package armo_builtins

import rego.v1

# Deny CNIs that don't support Network Policies.

deny contains msg if {
	# Filter out irrelevent resources
	obj = input[_]

	is_CNIInfo(obj)

	network_policy_not_supported(obj.data.CNINames)

	# filter out irrelevant host-sensor data
	obj_filtered := json.filter(obj, ["apiVersion", "kind", "metadata", "data/CNINames"])

	msg := {
		"alertMessage": "CNI doesn't support Network Policies.",
		"alertScore": 2,
		"failedPaths": [],
		"fixPaths": [],
		"fixCommand": "",
		"packagename": "armo_builtins",
		"alertObject": {"externalObjects": obj_filtered},
	}
}

is_CNIInfo(obj) if {
	obj.apiVersion == "hostdata.kubescape.cloud/v1beta0"
	obj.kind == "CNIInfo"
}

# deny if Flannel is running without calico
network_policy_not_supported(CNIs) if {
	"Flannel" in CNIs
	not "Calico" in CNIs
}

# deny if aws is running without any other CNI
network_policy_not_supported(CNIs) if {
	"aws" in CNIs
	count(CNIs) < 2
}
