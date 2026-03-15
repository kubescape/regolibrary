package armo_builtins

# input: network policies (NetworkPolicy, CiliumNetworkPolicy, CiliumClusterwideNetworkPolicy)
# fails if no network policies are defined in a certain namespace

deny[msga] {
	namespaces := [namespace | namespace = input[_]; namespace.kind == "Namespace"]
	namespace := namespaces[_]

	# Collect namespaces from all namespaced policies (NP + CNP)
	policy_names := [policy.metadata.namespace | policy = input[_]; is_network_policy_namespaced(policy)]

	# Collect clusterwide policies that legitimately protect all namespaces
	qualifying_ccnps := [policy | policy = input[_]; is_ccnp_cluster_wide_coverage(policy)]

	# Fail if: no namespaced policy in this namespace AND no qualifying CCNPs exist
	not list_contains(policy_names, namespace.metadata.name)
	count(qualifying_ccnps) == 0

	msga := {
		"alertMessage": sprintf("no policy is defined for namespace %v", [namespace.metadata.name]),
		"alertScore": 9,
		"packagename": "armo_builtins",
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [namespace],
		},
	}
}

is_network_policy_namespaced(policy) {
	policy.kind == "NetworkPolicy"
}

is_network_policy_namespaced(policy) {
	policy.kind == "CiliumNetworkPolicy"
}

# A CCNP legitimately protects all namespaces only if:
# 1. It selects all endpoints (empty endpointSelector or matchLabels: {})
# 2. It does not disable default-deny for both directions
# 3. It has at least ingress or egress rules defined

is_ccnp_cluster_wide_coverage(policy) {
	policy.kind == "CiliumClusterwideNetworkPolicy"
	ccnp_selects_all_endpoints(policy)
	not ccnp_default_deny_disabled(policy)
	ccnp_has_ingress_or_egress(policy)
}

# endpointSelector: { matchLabels: {} } (may also have matchExpressions: [])
ccnp_selects_all_endpoints(policy) {
	count(object.get(policy.spec.endpointSelector, "matchLabels", {})) == 0
	count(object.get(policy.spec.endpointSelector, "matchExpressions", [])) == 0
}

# endpointSelector: {} (empty object, no matchLabels key)
ccnp_selects_all_endpoints(policy) {
	count(policy.spec.endpointSelector) == 0
}

# enableDefaultDeny explicitly disables both directions
ccnp_default_deny_disabled(policy) {
	policy.spec.enableDefaultDeny.ingress == false
	policy.spec.enableDefaultDeny.egress == false
}

ccnp_has_ingress_or_egress(policy) {
	policy.spec.ingress
}

ccnp_has_ingress_or_egress(policy) {
	policy.spec.egress
}

list_contains(list, element) {
	some i
	list[i] == element
}