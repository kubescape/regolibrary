package armo_builtins

# Helper to identify all network policy types
is_network_policy(obj) {
	obj.kind == "NetworkPolicy"
}

is_network_policy(obj) {
	obj.kind == "CiliumNetworkPolicy"
}

is_network_policy(obj) {
	obj.kind == "CiliumClusterwideNetworkPolicy"
}

# Returns the list of CiliumNetworkPolicySpec entries, unifying the
# `spec:` (single) and `specs:` (list) forms documented for CNP/CCNP CRDs.
# Either field may be present; both is also legal in Cilium.
cilium_policy_specs(policy) = specs {
	from_spec := [s | s := policy.spec]
	from_specs := object.get(policy, "specs", [])
	specs := array.concat(from_spec, from_specs)
}

# For pods
deny[msga] {
	pods := [pod | pod = input[_]; pod.kind == "Pod"]
	networkpolicies := [networkpolicie | networkpolicie = input[_]; is_network_policy(networkpolicie)]
	pod := pods[_]
	network_policies_connected_to_pod := [networkpolicie | networkpolicie = networkpolicies[_]; pod_connected_to_network_policy(pod, networkpolicie)]
	count(network_policies_connected_to_pod) > 0
	goodPolicies := [goodpolicie | goodpolicie = network_policies_connected_to_pod[_]; is_ingerss_egress_policy(goodpolicie)]
	count(goodPolicies) < 1

	msga := {
		"alertMessage": sprintf("Pod: %v does not have ingress/egress defined", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [pod],
		},
	}
}

# For pods
deny[msga] {
	pods := [pod | pod = input[_]; pod.kind == "Pod"]
	networkpolicies := [networkpolicie | networkpolicie = input[_]; is_network_policy(networkpolicie)]
	pod := pods[_]
	network_policies_connected_to_pod := [networkpolicie | networkpolicie = networkpolicies[_]; pod_connected_to_network_policy(pod, networkpolicie)]
	count(network_policies_connected_to_pod) < 1

	msga := {
		"alertMessage": sprintf("Pod: %v does not have ingress/egress defined", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [pod],
		},
	}
}

# For workloads
deny[msga] {
	wl := input[_]
	spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	spec_template_spec_patterns[wl.kind]
	networkpolicies := [networkpolicie | networkpolicie = input[_]; is_network_policy(networkpolicie)]
	network_policies_connected_to_pod := [networkpolicie | networkpolicie = networkpolicies[_]; wlConnectedToNetworkPolicy(wl, networkpolicie)]
	count(network_policies_connected_to_pod) > 0
	goodPolicies := [goodpolicie | goodpolicie = network_policies_connected_to_pod[_]; is_ingerss_egress_policy(goodpolicie)]
	count(goodPolicies) < 1

	msga := {
		"alertMessage": sprintf("%v: %v has Pods which don't have ingress/egress defined", [wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [wl],
		},
	}
}

# For workloads
deny[msga] {
	wl := input[_]
	spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	spec_template_spec_patterns[wl.kind]
	networkpolicies := [networkpolicie | networkpolicie = input[_]; is_network_policy(networkpolicie)]
	network_policies_connected_to_pod := [networkpolicie | networkpolicie = networkpolicies[_]; wlConnectedToNetworkPolicy(wl, networkpolicie)]
	count(network_policies_connected_to_pod) < 1

	msga := {
		"alertMessage": sprintf("%v: %v has Pods which don't have ingress/egress defined", [wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [wl],
		},
	}
}

# For Cronjobs
deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
	networkpolicies := [networkpolicie | networkpolicie = input[_]; is_network_policy(networkpolicie)]
	network_policies_connected_to_pod := [networkpolicie | networkpolicie = networkpolicies[_]; cronjob_connected_to_network_policy(wl, networkpolicie)]
	count(network_policies_connected_to_pod) > 0
	goodPolicies := [goodpolicie | goodpolicie = network_policies_connected_to_pod[_]; is_ingerss_egress_policy(goodpolicie)]
	count(goodPolicies) < 1

	msga := {
		"alertMessage": sprintf("%v: %v has Pods which don't have ingress/egress defined", [wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [wl],
		},
	}
}

# For Cronjobs
deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
	networkpolicies := [networkpolicie | networkpolicie = input[_]; is_network_policy(networkpolicie)]
	network_policies_connected_to_pod := [networkpolicie | networkpolicie = networkpolicies[_]; cronjob_connected_to_network_policy(wl, networkpolicie)]
	count(network_policies_connected_to_pod) < 1

	msga := {
		"alertMessage": sprintf("%v: %v has Pods which don't have ingress/egress defined", [wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [wl],
		},
	}
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

# --- Pod connection checks ---

# Standard NetworkPolicy with podSelector (with labels)
pod_connected_to_network_policy(pod, networkpolicie) {
	networkpolicie.kind == "NetworkPolicy"
	is_same_namespace(networkpolicie.metadata, pod.metadata)
	count(networkpolicie.spec.podSelector) > 0
	count({x | networkpolicie.spec.podSelector.matchLabels[x] == pod.metadata.labels[x]}) == count(networkpolicie.spec.podSelector.matchLabels)
}

# Standard NetworkPolicy with empty podSelector (selects all pods in namespace)
pod_connected_to_network_policy(pod, networkpolicie) {
	networkpolicie.kind == "NetworkPolicy"
	is_same_namespace(networkpolicie.metadata, pod.metadata)
	count(networkpolicie.spec.podSelector) == 0
}

# CiliumNetworkPolicy: any spec (singular `spec:` or any entry of `specs:`) matches the pod
pod_connected_to_network_policy(pod, networkpolicie) {
	networkpolicie.kind == "CiliumNetworkPolicy"
	is_same_namespace(networkpolicie.metadata, pod.metadata)
	spec := cilium_policy_specs(networkpolicie)[_]
	cilium_endpoint_selector_matches(spec, object.get(pod.metadata, "labels", {}))
}

# CiliumClusterwideNetworkPolicy: same, no namespace check
pod_connected_to_network_policy(pod, networkpolicie) {
	networkpolicie.kind == "CiliumClusterwideNetworkPolicy"
	spec := cilium_policy_specs(networkpolicie)[_]
	cilium_endpoint_selector_matches(spec, object.get(pod.metadata, "labels", {}))
}

# --- Workload connection checks ---

# Standard NetworkPolicy with empty podSelector
wlConnectedToNetworkPolicy(wl, networkpolicie) {
	networkpolicie.kind == "NetworkPolicy"
	is_same_namespace(wl.metadata, networkpolicie.metadata)
	count(networkpolicie.spec.podSelector) == 0
}

# Standard NetworkPolicy with podSelector (with labels)
wlConnectedToNetworkPolicy(wl, networkpolicie) {
	networkpolicie.kind == "NetworkPolicy"
	is_same_namespace(wl.metadata, networkpolicie.metadata)
	count(networkpolicie.spec.podSelector) > 0
	count({x | networkpolicie.spec.podSelector.matchLabels[x] == wl.spec.template.metadata.labels[x]}) == count(networkpolicie.spec.podSelector.matchLabels)
}

# CiliumNetworkPolicy
wlConnectedToNetworkPolicy(wl, networkpolicie) {
	networkpolicie.kind == "CiliumNetworkPolicy"
	is_same_namespace(wl.metadata, networkpolicie.metadata)
	spec := cilium_policy_specs(networkpolicie)[_]
	cilium_endpoint_selector_matches(spec, object.get(wl.spec.template.metadata, "labels", {}))
}

# CiliumClusterwideNetworkPolicy
wlConnectedToNetworkPolicy(wl, networkpolicie) {
	networkpolicie.kind == "CiliumClusterwideNetworkPolicy"
	spec := cilium_policy_specs(networkpolicie)[_]
	cilium_endpoint_selector_matches(spec, object.get(wl.spec.template.metadata, "labels", {}))
}

# --- CronJob connection checks ---

# Standard NetworkPolicy with empty podSelector
cronjob_connected_to_network_policy(cj, networkpolicie) {
	networkpolicie.kind == "NetworkPolicy"
	is_same_namespace(cj.metadata, networkpolicie.metadata)
	count(networkpolicie.spec.podSelector) == 0
}

# Standard NetworkPolicy with podSelector (with labels)
cronjob_connected_to_network_policy(cj, networkpolicie) {
	networkpolicie.kind == "NetworkPolicy"
	is_same_namespace(cj.metadata, networkpolicie.metadata)
	count(networkpolicie.spec.podSelector) > 0
	count({x | networkpolicie.spec.podSelector.matchLabels[x] == cj.spec.jobTemplate.spec.template.metadata.labels[x]}) == count(networkpolicie.spec.podSelector.matchLabels)
}

# CiliumNetworkPolicy
cronjob_connected_to_network_policy(cj, networkpolicie) {
	networkpolicie.kind == "CiliumNetworkPolicy"
	is_same_namespace(cj.metadata, networkpolicie.metadata)
	spec := cilium_policy_specs(networkpolicie)[_]
	cilium_endpoint_selector_matches(spec, object.get(cj.spec.jobTemplate.spec.template.metadata, "labels", {}))
}

# CiliumClusterwideNetworkPolicy
cronjob_connected_to_network_policy(cj, networkpolicie) {
	networkpolicie.kind == "CiliumClusterwideNetworkPolicy"
	spec := cilium_policy_specs(networkpolicie)[_]
	cilium_endpoint_selector_matches(spec, object.get(cj.spec.jobTemplate.spec.template.metadata, "labels", {}))
}

# --- Ingress/Egress policy checks ---

# Standard NetworkPolicy: check policyTypes
is_ingerss_egress_policy(networkpolicie) {
	networkpolicie.kind == "NetworkPolicy"
	list_contains(networkpolicie.spec.policyTypes, "Ingress")
}

is_ingerss_egress_policy(networkpolicie) {
	networkpolicie.kind == "NetworkPolicy"
	list_contains(networkpolicie.spec.policyTypes, "Egress")
}

# CiliumNetworkPolicy / CCNP: presence of `ingress`/`egress` on any spec entry
# determines direction (CNP/CCNP have no `policyTypes`).
is_ingerss_egress_policy(networkpolicie) {
	networkpolicie.kind == "CiliumNetworkPolicy"
	spec := cilium_policy_specs(networkpolicie)[_]
	spec.ingress
}

is_ingerss_egress_policy(networkpolicie) {
	networkpolicie.kind == "CiliumNetworkPolicy"
	spec := cilium_policy_specs(networkpolicie)[_]
	spec.egress
}

is_ingerss_egress_policy(networkpolicie) {
	networkpolicie.kind == "CiliumClusterwideNetworkPolicy"
	spec := cilium_policy_specs(networkpolicie)[_]
	spec.ingress
}

is_ingerss_egress_policy(networkpolicie) {
	networkpolicie.kind == "CiliumClusterwideNetworkPolicy"
	spec := cilium_policy_specs(networkpolicie)[_]
	spec.egress
}

list_contains(list, element) {
	some i
	list[i] == element
}
