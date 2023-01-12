package armo_builtins


# Deny CNIs that don't support Network Policies.

deny[msg] {
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

is_CNIInfo(obj) {
	obj.apiVersion == "hostdata.kubescape.cloud/v1beta0"
	obj.kind == "CNIInfo"
}


# deny if Flannel is running without calico
network_policy_not_supported(CNIs) {
	contains(CNIs, "Flannel")
	not contains(CNIs, "Calico")
}

# deny if aws is running without any other CNI
network_policy_not_supported(CNIs) {
	contains(CNIs, "aws")
	count(CNIs) < 2
}


contains(ls, elem) {
  ls[_] = elem
}