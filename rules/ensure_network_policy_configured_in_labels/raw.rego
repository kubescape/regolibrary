package armo_builtins


deny[msga] {

    resources := get_resources(input[_])
	resource := resources[_]

	# getting all networkpolicies
	networkpolicies := [networkpolicy |  networkpolicy= input[_]; networkpolicy.kind == "NetworkPolicy"]
	
	# getting all networkpolicies that are connected to workload with label
	network_policies_connected_to_workload := [networkpolicy |  networkpolicy= networkpolicies[_];  connected_to_network_policy(resource, networkpolicy)]

	# we expect the number of resources to be equal to the number of networkpolicies connected to the workload. If not, deny.
	not count(resources) == count(network_policies_connected_to_workload)
	
	msga := {
		"alertMessage": sprintf("%v: no networkpolicy configured in labels", [resource.metadata.name]),
		"packagename": "armo_builtins",
		"failedPaths": [],
		"fixPaths":[],
		"alertObject": {
			"k8sApiObjects": [resource]
		}
	}
}


# get_resources returns all resources of kind Deployment, ReplicaSet, DaemonSet, StatefulSet, Job, Pod, CronJob
get_resources(resources) := result {
	resource_kinds := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	resource_kinds[resources.kind]
	result = [resources]
}

# get_resources returns all resources of kind Pod
get_resources(resources) := result {
	resources.kind == "Pod"
	result = [resources]
}

# get_resources returns all resources of kind CronJob
get_resources(resources) := result {
	resources.kind == "CronJob"
	result = [resources]
}

# connected_to_network_policy returns true if the resource is connected to the networkpolicy
connected_to_network_policy(wl, networkpolicy){
	resource_kinds := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	resource_kinds[wl.kind]
	is_same_namespace(networkpolicy.metadata, wl.metadata)
	count(networkpolicy.spec.podSelector) > 0
    count({x | networkpolicy.spec.podSelector.matchLabels[x] == wl.spec.template.metadata.labels[x]}) == count(networkpolicy.spec.podSelector.matchLabels)
}

# connected_to_network_policy returns true if the resource is connected to the networkpolicy
connected_to_network_policy(wl, networkpolicy){
	wl.kind == "Pod"
	is_same_namespace(networkpolicy.metadata, wl.metadata)
    count(networkpolicy.spec.podSelector) > 0
    count({x | networkpolicy.spec.podSelector.matchLabels[x] == wl.metadata.labels[x]}) == count(networkpolicy.spec.podSelector.matchLabels)
}

# connected_to_network_policy returns true if the resource is connected to the networkpolicy
connected_to_network_policy(wl, networkpolicy){
	wl.kind == "CronJob"
	is_same_namespace(networkpolicy.metadata, wl.metadata)
	count(networkpolicy.spec.podSelector) > 0
    count({x | networkpolicy.spec.podSelector.matchLabels[x] == wl.spec.jobTemplate.spec.template.metadata.labels[x]}) == count(networkpolicy.spec.podSelector.matchLabels)
}

# connected_to_network_policy returns true if the NetworkPolicy has no podSelector.
# if the NetworkPolicy has no podSelector, it is applied to all workloads in the namespace of the NetworkPolicy
connected_to_network_policy(wl, networkpolicy){
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