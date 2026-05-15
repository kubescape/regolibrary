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

# Returns the list of CiliumNetworkPolicySpec entries, unifying the
# `spec:` (single) and `specs:` (list) forms documented for CNP/CCNP CRDs.
# Either field may be present; both is also legal in Cilium.
cilium_policy_specs(policy) = specs {
	from_spec := [s | s := policy.spec]
	from_specs := object.get(policy, "specs", [])
	specs := array.concat(from_spec, from_specs)
}

# A CCNP legitimately protects all namespaces only if at least one of its specs:
# 1. Selects all endpoints (empty endpointSelector or matchLabels: {})
# 2. Does not disable default-deny for both directions
# 3. Has at least ingress or egress rules defined
# (enableDefaultDeny, endpointSelector, ingress, egress are all per-CiliumNetworkPolicySpec.)

is_ccnp_cluster_wide_coverage(policy) {
	policy.kind == "CiliumClusterwideNetworkPolicy"
	spec := cilium_policy_specs(policy)[_]
	ccnp_spec_selects_all_endpoints(spec)
	not ccnp_spec_default_deny_disabled(spec)
	ccnp_spec_has_ingress_or_egress(spec)
}

# Covers both `endpointSelector: {}` and `endpointSelector: { matchLabels: {} }`
# (and tolerates an empty `matchExpressions: []`).
ccnp_spec_selects_all_endpoints(spec) {
	count(object.get(spec.endpointSelector, "matchLabels", {})) == 0
	count(object.get(spec.endpointSelector, "matchExpressions", [])) == 0
}

# enableDefaultDeny explicitly disables both directions on this spec
ccnp_spec_default_deny_disabled(spec) {
	spec.enableDefaultDeny.ingress == false
	spec.enableDefaultDeny.egress == false
}

ccnp_spec_has_ingress_or_egress(spec) {
	spec.ingress
}

ccnp_spec_has_ingress_or_egress(spec) {
	spec.egress
}

list_contains(list, element) {
	some i
	list[i] == element
}
