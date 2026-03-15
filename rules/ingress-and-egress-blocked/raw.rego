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

# CiliumNetworkPolicy with endpointSelector (with labels)
pod_connected_to_network_policy(pod, networkpolicie) {
	networkpolicie.kind == "CiliumNetworkPolicy"
	is_same_namespace(networkpolicie.metadata, pod.metadata)
	count(networkpolicie.spec.endpointSelector.matchLabels) > 0
	count({x | networkpolicie.spec.endpointSelector.matchLabels[x] == pod.metadata.labels[x]}) == count(networkpolicie.spec.endpointSelector.matchLabels)
}

# CiliumNetworkPolicy with endpointSelector: { matchLabels: {} }
pod_connected_to_network_policy(pod, networkpolicie) {
	networkpolicie.kind == "CiliumNetworkPolicy"
	is_same_namespace(networkpolicie.metadata, pod.metadata)
	count(networkpolicie.spec.endpointSelector.matchLabels) == 0
}

# CiliumNetworkPolicy with endpointSelector: {} (empty object, no matchLabels key)
pod_connected_to_network_policy(pod, networkpolicie) {
	networkpolicie.kind == "CiliumNetworkPolicy"
	is_same_namespace(networkpolicie.metadata, pod.metadata)
	count(networkpolicie.spec.endpointSelector) == 0
}

# CiliumClusterwideNetworkPolicy with endpointSelector (with labels, no namespace check)
pod_connected_to_network_policy(pod, networkpolicie) {
	networkpolicie.kind == "CiliumClusterwideNetworkPolicy"
	count(networkpolicie.spec.endpointSelector.matchLabels) > 0
	count({x | networkpolicie.spec.endpointSelector.matchLabels[x] == pod.metadata.labels[x]}) == count(networkpolicie.spec.endpointSelector.matchLabels)
}

# CiliumClusterwideNetworkPolicy with endpointSelector: { matchLabels: {} }
pod_connected_to_network_policy(pod, networkpolicie) {
	networkpolicie.kind == "CiliumClusterwideNetworkPolicy"
	count(networkpolicie.spec.endpointSelector.matchLabels) == 0
}

# CiliumClusterwideNetworkPolicy with endpointSelector: {} (empty object)
pod_connected_to_network_policy(pod, networkpolicie) {
	networkpolicie.kind == "CiliumClusterwideNetworkPolicy"
	count(networkpolicie.spec.endpointSelector) == 0
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

# CiliumNetworkPolicy with endpointSelector (with labels)
wlConnectedToNetworkPolicy(wl, networkpolicie) {
	networkpolicie.kind == "CiliumNetworkPolicy"
	is_same_namespace(wl.metadata, networkpolicie.metadata)
	count(networkpolicie.spec.endpointSelector.matchLabels) > 0
	count({x | networkpolicie.spec.endpointSelector.matchLabels[x] == wl.spec.template.metadata.labels[x]}) == count(networkpolicie.spec.endpointSelector.matchLabels)
}

# CiliumNetworkPolicy with endpointSelector: { matchLabels: {} }
wlConnectedToNetworkPolicy(wl, networkpolicie) {
	networkpolicie.kind == "CiliumNetworkPolicy"
	is_same_namespace(wl.metadata, networkpolicie.metadata)
	count(networkpolicie.spec.endpointSelector.matchLabels) == 0
}

# CiliumNetworkPolicy with endpointSelector: {} (empty object, no matchLabels key)
wlConnectedToNetworkPolicy(wl, networkpolicie) {
	networkpolicie.kind == "CiliumNetworkPolicy"
	is_same_namespace(wl.metadata, networkpolicie.metadata)
	count(networkpolicie.spec.endpointSelector) == 0
}

# CiliumClusterwideNetworkPolicy with endpointSelector (with labels, no namespace check)
wlConnectedToNetworkPolicy(wl, networkpolicie) {
	networkpolicie.kind == "CiliumClusterwideNetworkPolicy"
	count(networkpolicie.spec.endpointSelector.matchLabels) > 0
	count({x | networkpolicie.spec.endpointSelector.matchLabels[x] == wl.spec.template.metadata.labels[x]}) == count(networkpolicie.spec.endpointSelector.matchLabels)
}

# CiliumClusterwideNetworkPolicy with endpointSelector: { matchLabels: {} }
wlConnectedToNetworkPolicy(wl, networkpolicie) {
	networkpolicie.kind == "CiliumClusterwideNetworkPolicy"
	count(networkpolicie.spec.endpointSelector.matchLabels) == 0
}

# CiliumClusterwideNetworkPolicy with endpointSelector: {} (empty object)
wlConnectedToNetworkPolicy(wl, networkpolicie) {
	networkpolicie.kind == "CiliumClusterwideNetworkPolicy"
	count(networkpolicie.spec.endpointSelector) == 0
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

# CiliumNetworkPolicy with endpointSelector (with labels)
cronjob_connected_to_network_policy(cj, networkpolicie) {
	networkpolicie.kind == "CiliumNetworkPolicy"
	is_same_namespace(cj.metadata, networkpolicie.metadata)
	count(networkpolicie.spec.endpointSelector.matchLabels) > 0
	count({x | networkpolicie.spec.endpointSelector.matchLabels[x] == cj.spec.jobTemplate.spec.template.metadata.labels[x]}) == count(networkpolicie.spec.endpointSelector.matchLabels)
}

# CiliumNetworkPolicy with endpointSelector: { matchLabels: {} }
cronjob_connected_to_network_policy(cj, networkpolicie) {
	networkpolicie.kind == "CiliumNetworkPolicy"
	is_same_namespace(cj.metadata, networkpolicie.metadata)
	count(networkpolicie.spec.endpointSelector.matchLabels) == 0
}

# CiliumNetworkPolicy with endpointSelector: {} (empty object, no matchLabels key)
cronjob_connected_to_network_policy(cj, networkpolicie) {
	networkpolicie.kind == "CiliumNetworkPolicy"
	is_same_namespace(cj.metadata, networkpolicie.metadata)
	count(networkpolicie.spec.endpointSelector) == 0
}

# CiliumClusterwideNetworkPolicy with endpointSelector (with labels, no namespace check)
cronjob_connected_to_network_policy(cj, networkpolicie) {
	networkpolicie.kind == "CiliumClusterwideNetworkPolicy"
	count(networkpolicie.spec.endpointSelector.matchLabels) > 0
	count({x | networkpolicie.spec.endpointSelector.matchLabels[x] == cj.spec.jobTemplate.spec.template.metadata.labels[x]}) == count(networkpolicie.spec.endpointSelector.matchLabels)
}

# CiliumClusterwideNetworkPolicy with endpointSelector: { matchLabels: {} }
cronjob_connected_to_network_policy(cj, networkpolicie) {
	networkpolicie.kind == "CiliumClusterwideNetworkPolicy"
	count(networkpolicie.spec.endpointSelector.matchLabels) == 0
}

# CiliumClusterwideNetworkPolicy with endpointSelector: {} (empty object)
cronjob_connected_to_network_policy(cj, networkpolicie) {
	networkpolicie.kind == "CiliumClusterwideNetworkPolicy"
	count(networkpolicie.spec.endpointSelector) == 0
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

# CiliumNetworkPolicy: presence of spec.ingress/spec.egress determines direction
is_ingerss_egress_policy(networkpolicie) {
	networkpolicie.kind == "CiliumNetworkPolicy"
	networkpolicie.spec.ingress
}

is_ingerss_egress_policy(networkpolicie) {
	networkpolicie.kind == "CiliumNetworkPolicy"
	networkpolicie.spec.egress
}

# CiliumClusterwideNetworkPolicy: same checks, no free pass
is_ingerss_egress_policy(networkpolicie) {
	networkpolicie.kind == "CiliumClusterwideNetworkPolicy"
	networkpolicie.spec.ingress
}

is_ingerss_egress_policy(networkpolicie) {
	networkpolicie.kind == "CiliumClusterwideNetworkPolicy"
	networkpolicie.spec.egress
}

list_contains(list, element) {
	some i
	list[i] == element
}