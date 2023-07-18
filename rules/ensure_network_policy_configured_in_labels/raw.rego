package armo_builtins


deny[msga] {
	workload := input[_]
	workload_kinds := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job", "Pod", "CronJob"}
	workload_kinds[workload.kind]

	networkpolicies := [networkpolicy | networkpolicy = input[_]; networkpolicy.kind == "NetworkPolicy"]
	not connected_to_any_network_policy(workload, networkpolicies)
	
	msga := {
		"alertMessage": sprintf("%v: no networkpolicy configured in labels", [workload.metadata.name]),
		"packagename": "armo_builtins",
		"failedPaths": [],
		"fixPaths":[],
		"alertObject": {
			"k8sApiObjects": [workload]
		}
	}
}


connected_to_any_network_policy(workload, networkpolicies){
	connected_to_network_policy(workload, networkpolicies[_])
}

# connected_to_network_policy returns true if the workload is connected to the networkpolicy
connected_to_network_policy(wl, networkpolicy){
	workload_kinds := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	workload_kinds[wl.kind]
	is_same_namespace(networkpolicy.metadata, wl.metadata)
	count(networkpolicy.spec.podSelector) > 0
    count({x | networkpolicy.spec.podSelector.matchLabels[x] == wl.spec.template.metadata.labels[x]}) == count(networkpolicy.spec.podSelector.matchLabels)
}

# connected_to_network_policy returns true if the workload is connected to the networkpolicy
connected_to_network_policy(wl, networkpolicy){
	wl.kind == "Pod"
	is_same_namespace(networkpolicy.metadata, wl.metadata)
    count(networkpolicy.spec.podSelector) > 0
    count({x | networkpolicy.spec.podSelector.matchLabels[x] == wl.metadata.labels[x]}) == count(networkpolicy.spec.podSelector.matchLabels)
}

# connected_to_network_policy returns true if the workload is connected to the networkpolicy
connected_to_network_policy(wl, networkpolicy){
	wl.kind == "CronJob"
	is_same_namespace(networkpolicy.metadata, wl.metadata)
	count(networkpolicy.spec.podSelector) > 0
    count({x | networkpolicy.spec.podSelector.matchLabels[x] == wl.spec.jobTemplate.spec.template.metadata.labels[x]}) == count(networkpolicy.spec.podSelector.matchLabels)
}

# connected_to_network_policy returns true if the NetworkPolicy has no podSelector.
# if the NetworkPolicy has no podSelector, it is applied to all workloads in the namespace of the NetworkPolicy
connected_to_network_policy(wl, networkpolicy){
	is_same_namespace(networkpolicy.metadata, wl.metadata)
    count(networkpolicy.spec.podSelector) == 0
}


is_same_namespace(metadata1, metadata2) {
	metadata1.namespace == metadata2.namespace
}

is_same_namespace(metadata1, metadata2) {
	not metadata1.namespace
	not metadata2.namespace
}

is_same_namespace(metadata1, metadata2) {
	not metadata2.namespace
	metadata1.namespace == "default"
}

is_same_namespace(metadata1, metadata2) {
	not metadata1.namespace
	metadata2.namespace == "default"
}