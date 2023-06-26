package armo_builtins

import future.keywords.in

# EKS supports Calico and Cilium add-ons, both supports Network Policy.
# Deny if at least on of them is not in the list of CNINames.

deny[msg] {
	# Filter out irrelevent resources
	obj = input[_]

    is_CNIInfos(obj)

	not "Calico" in obj.data.CNINames
	not "Cilium" in obj.data.CNINames

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

is_CNIInfos(obj) {
	obj.apiVersion == "hostdata.kubescape.cloud/v1beta0"
	obj.kind == "CNIInfo"
}
