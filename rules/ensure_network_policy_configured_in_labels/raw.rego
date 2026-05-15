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

# Returns the list of CiliumNetworkPolicySpec entries, unifying the
# `spec:` (single) and `specs:` (list) forms documented for CNP/CCNP CRDs.
# Either field may be present; both is also legal in Cilium.
cilium_policy_specs(policy) = specs {
	from_spec := [s | s := policy.spec]
	from_specs := object.get(policy, "specs", [])
	specs := array.concat(from_spec, from_specs)
}

connected_to_any_network_policy(workload, networkpolicies){
	connected_to_network_policy(workload, networkpolicies[_])
}

# --- Cilium endpointSelector match (shared across pod/workload/cronjob) ---

# matchLabels with keys: every key on the selector must equal the corresponding label.
cilium_endpoint_selector_matches(spec, labels) {
	count(spec.endpointSelector.matchLabels) > 0
	count({x | spec.endpointSelector.matchLabels[x] == labels[x]}) == count(spec.endpointSelector.matchLabels)
}

# Selects-all: covers `endpointSelector: {}` and `endpointSelector: { matchLabels: {} }`.
# A non-empty matchExpressions makes the selector selective, NOT match-all
# (per Kubernetes LabelSelector: matchLabels AND matchExpressions must both match).
cilium_endpoint_selector_matches(spec, _) {
	count(object.get(spec.endpointSelector, "matchLabels", {})) == 0
	count(object.get(spec.endpointSelector, "matchExpressions", [])) == 0
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

# CiliumNetworkPolicy
connected_to_network_policy(wl, networkpolicy){
	workload_kinds := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	workload_kinds[wl.kind]
	is_same_namespace(networkpolicy.metadata, wl.metadata)
	networkpolicy.kind == "CiliumNetworkPolicy"
	spec := cilium_policy_specs(networkpolicy)[_]
	cilium_endpoint_selector_matches(spec, object.get(wl.spec.template.metadata, "labels", {}))
}

# CiliumClusterwideNetworkPolicy (no namespace check)
connected_to_network_policy(wl, networkpolicy){
	workload_kinds := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	workload_kinds[wl.kind]
	networkpolicy.kind == "CiliumClusterwideNetworkPolicy"
	spec := cilium_policy_specs(networkpolicy)[_]
	cilium_endpoint_selector_matches(spec, object.get(wl.spec.template.metadata, "labels", {}))
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

# CiliumNetworkPolicy
connected_to_network_policy(wl, networkpolicy){
	wl.kind == "Pod"
	is_same_namespace(networkpolicy.metadata, wl.metadata)
	networkpolicy.kind == "CiliumNetworkPolicy"
	spec := cilium_policy_specs(networkpolicy)[_]
	cilium_endpoint_selector_matches(spec, object.get(wl.metadata, "labels", {}))
}

# CiliumClusterwideNetworkPolicy (no namespace check)
connected_to_network_policy(wl, networkpolicy){
	wl.kind == "Pod"
	networkpolicy.kind == "CiliumClusterwideNetworkPolicy"
	spec := cilium_policy_specs(networkpolicy)[_]
	cilium_endpoint_selector_matches(spec, object.get(wl.metadata, "labels", {}))
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

# CiliumNetworkPolicy
connected_to_network_policy(wl, networkpolicy){
	wl.kind == "CronJob"
	is_same_namespace(networkpolicy.metadata, wl.metadata)
	networkpolicy.kind == "CiliumNetworkPolicy"
	spec := cilium_policy_specs(networkpolicy)[_]
	cilium_endpoint_selector_matches(spec, object.get(wl.spec.jobTemplate.spec.template.metadata, "labels", {}))
}

# CiliumClusterwideNetworkPolicy (no namespace check)
connected_to_network_policy(wl, networkpolicy){
	wl.kind == "CronJob"
	networkpolicy.kind == "CiliumClusterwideNetworkPolicy"
	spec := cilium_policy_specs(networkpolicy)[_]
	cilium_endpoint_selector_matches(spec, object.get(wl.spec.jobTemplate.spec.template.metadata, "labels", {}))
}

# --- Empty selector for standard NetworkPolicy (selects all in namespace) ---

connected_to_network_policy(wl, networkpolicy){
	is_same_namespace(networkpolicy.metadata, wl.metadata)
	networkpolicy.kind == "NetworkPolicy"
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
