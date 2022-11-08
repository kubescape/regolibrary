package armo_builtins


# Deny CNIs that don't support Network Policies.
# Deny when CNIName in input and in CNINotSupportsNetworkPolicies list.
# Pass when CNIName not in input, or when CNIName in input but not in CNINotSupportsNetworkPolicies

deny[msg] {
	# Filter out irrelevent resources
	obj = input[_]
    is_control_plane_info(obj)
  
	# list of CNIs not supporting support Network Policies
 	CNINotSupportsNetworkPolicies := ["Flannel"]

	# filter CNIs not supporting Network Policies
    CNINotSupportsNetworkPolicies[_] = obj.data.CNIName

	# filter out irrelevant host-sensor data
    obj_filtered := json.filter(obj, ["apiVersion", "kind", "metadata", "data/CNIName"])
    
	alert := sprintf("''%s' CNI doesn't support Network Policies.", [obj.data.CNIName])

    msg := {
		"alertMessage": alert,
		"alertScore": 2,
		"failedPaths": [],
		"fixPaths": [],
		"fixCommand": "",
		"packagename": "armo_builtins",
		"alertObject": {"externalObjects": obj_filtered},

	}
}

is_control_plane_info(obj) {
	obj.apiVersion == "hostdata.kubescape.cloud/v1beta0"
	obj.kind == "ControlPlaneInfo"
}
