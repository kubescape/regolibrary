package armo_builtins


deny[msga] {
	workload := input[_]
	workload_kinds := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job", "Pod", "CronJob"}
	workload_kinds[workload.kind]

	networkpolicies := [networkpolicy | networkpolicy = input[_]; is_network_policy(networkpolicy)]
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

# Helper function to identify all network policy types
is_network_policy(policy) {
	policy.kind == "NetworkPolicy"
}

is_network_policy(policy) {
	policy.kind == "CiliumNetworkPolicy"
}

is_network_policy(policy) {
	policy.kind == "CiliumClusterwideNetworkPolicy"
}


connected_to_any_network_policy(workload, networkpolicies){
	connected_to_network_policy(workload, networkpolicies[_])
}

# --- Workload connection checks (Deployment, ReplicaSet, DaemonSet, StatefulSet, Job) ---

# Standard NetworkPolicy with podSelector (with labels)
connected_to_network_policy(wl, networkpolicy){
	workload_kinds := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	workload_kinds[wl.kind]
	is_same_namespace(networkpolicy.metadata, wl.metadata)
	networkpolicy.kind == "NetworkPolicy"
	count(networkpolicy.spec.podSelector) > 0
    count({x | networkpolicy.spec.podSelector.matchLabels[x] == wl.spec.template.metadata.labels[x]}) == count(networkpolicy.spec.podSelector.matchLabels)
}

# CiliumNetworkPolicy with endpointSelector (with labels)
connected_to_network_policy(wl, networkpolicy){
	workload_kinds := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	workload_kinds[wl.kind]
	is_same_namespace(networkpolicy.metadata, wl.metadata)
	networkpolicy.kind == "CiliumNetworkPolicy"
	count(networkpolicy.spec.endpointSelector.matchLabels) > 0
    count({x | networkpolicy.spec.endpointSelector.matchLabels[x] == wl.spec.template.metadata.labels[x]}) == count(networkpolicy.spec.endpointSelector.matchLabels)
}

# CiliumClusterwideNetworkPolicy with endpointSelector (with labels, no namespace check)
connected_to_network_policy(wl, networkpolicy){
	workload_kinds := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	workload_kinds[wl.kind]
	networkpolicy.kind == "CiliumClusterwideNetworkPolicy"
	count(networkpolicy.spec.endpointSelector.matchLabels) > 0
    count({x | networkpolicy.spec.endpointSelector.matchLabels[x] == wl.spec.template.metadata.labels[x]}) == count(networkpolicy.spec.endpointSelector.matchLabels)
}

# --- Pod connection checks ---

# Standard NetworkPolicy with podSelector (with labels)
connected_to_network_policy(wl, networkpolicy){
	wl.kind == "Pod"
	is_same_namespace(networkpolicy.metadata, wl.metadata)
	networkpolicy.kind == "NetworkPolicy"
    count(networkpolicy.spec.podSelector) > 0
    count({x | networkpolicy.spec.podSelector.matchLabels[x] == wl.metadata.labels[x]}) == count(networkpolicy.spec.podSelector.matchLabels)
}

# CiliumNetworkPolicy with endpointSelector (with labels)
connected_to_network_policy(wl, networkpolicy){
	wl.kind == "Pod"
	is_same_namespace(networkpolicy.metadata, wl.metadata)
	networkpolicy.kind == "CiliumNetworkPolicy"
    count(networkpolicy.spec.endpointSelector.matchLabels) > 0
    count({x | networkpolicy.spec.endpointSelector.matchLabels[x] == wl.metadata.labels[x]}) == count(networkpolicy.spec.endpointSelector.matchLabels)
}

# CiliumClusterwideNetworkPolicy with endpointSelector (with labels, no namespace check)
connected_to_network_policy(wl, networkpolicy){
	wl.kind == "Pod"
	networkpolicy.kind == "CiliumClusterwideNetworkPolicy"
    count(networkpolicy.spec.endpointSelector.matchLabels) > 0
    count({x | networkpolicy.spec.endpointSelector.matchLabels[x] == wl.metadata.labels[x]}) == count(networkpolicy.spec.endpointSelector.matchLabels)
}

# --- CronJob connection checks ---

# Standard NetworkPolicy with podSelector (with labels)
connected_to_network_policy(wl, networkpolicy){
	wl.kind == "CronJob"
	is_same_namespace(networkpolicy.metadata, wl.metadata)
	networkpolicy.kind == "NetworkPolicy"
	count(networkpolicy.spec.podSelector) > 0
    count({x | networkpolicy.spec.podSelector.matchLabels[x] == wl.spec.jobTemplate.spec.template.metadata.labels[x]}) == count(networkpolicy.spec.podSelector.matchLabels)
}

# CiliumNetworkPolicy with endpointSelector (with labels)
connected_to_network_policy(wl, networkpolicy){
	wl.kind == "CronJob"
	is_same_namespace(networkpolicy.metadata, wl.metadata)
	networkpolicy.kind == "CiliumNetworkPolicy"
	count(networkpolicy.spec.endpointSelector.matchLabels) > 0
    count({x | networkpolicy.spec.endpointSelector.matchLabels[x] == wl.spec.jobTemplate.spec.template.metadata.labels[x]}) == count(networkpolicy.spec.endpointSelector.matchLabels)
}

# CiliumClusterwideNetworkPolicy with endpointSelector (with labels, no namespace check)
connected_to_network_policy(wl, networkpolicy){
	wl.kind == "CronJob"
	networkpolicy.kind == "CiliumClusterwideNetworkPolicy"
	count(networkpolicy.spec.endpointSelector.matchLabels) > 0
    count({x | networkpolicy.spec.endpointSelector.matchLabels[x] == wl.spec.jobTemplate.spec.template.metadata.labels[x]}) == count(networkpolicy.spec.endpointSelector.matchLabels)
}

# --- Empty selector checks (policy applies to all workloads) ---

# NetworkPolicy with empty podSelector (selects all in namespace)
connected_to_network_policy(wl, networkpolicy){
	is_same_namespace(networkpolicy.metadata, wl.metadata)
	networkpolicy.kind == "NetworkPolicy"
    count(networkpolicy.spec.podSelector) == 0
}

# CiliumNetworkPolicy with endpointSelector: { matchLabels: {} }
connected_to_network_policy(wl, networkpolicy){
	is_same_namespace(networkpolicy.metadata, wl.metadata)
	networkpolicy.kind == "CiliumNetworkPolicy"
    count(networkpolicy.spec.endpointSelector.matchLabels) == 0
}

# CiliumNetworkPolicy with endpointSelector: {} (empty object, no matchLabels key)
connected_to_network_policy(wl, networkpolicy){
	is_same_namespace(networkpolicy.metadata, wl.metadata)
	networkpolicy.kind == "CiliumNetworkPolicy"
    count(networkpolicy.spec.endpointSelector) == 0
}

# CiliumClusterwideNetworkPolicy with endpointSelector: { matchLabels: {} } (all pods cluster-wide)
connected_to_network_policy(wl, networkpolicy){
	networkpolicy.kind == "CiliumClusterwideNetworkPolicy"
    count(networkpolicy.spec.endpointSelector.matchLabels) == 0
}

# CiliumClusterwideNetworkPolicy with endpointSelector: {} (empty object, all pods cluster-wide)
connected_to_network_policy(wl, networkpolicy){
	networkpolicy.kind == "CiliumClusterwideNetworkPolicy"
    count(networkpolicy.spec.endpointSelector) == 0
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