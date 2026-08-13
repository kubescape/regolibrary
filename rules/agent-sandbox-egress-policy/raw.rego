# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

_management(template) := m if {
	m := object.get(template, ["spec", "networkPolicyManagement"], "Managed")
	m != null
} else := "Managed"

_network_policy(template) := object.get(template, ["spec", "networkPolicy"], null)

_name(template) := object.get(template, ["metadata", "name"], "<unnamed>")

_egress_rule_scoped(rule) if {
	to := object.get(rule, "to", null)
	is_array(to)
	count(to) > 0

	count([peer | peer := to[_]; not _has_peer_selector(peer)]) == 0
}

_has_peer_selector(peer) if {
	ipb := object.get(peer, "ipBlock", null)
	is_object(ipb)
	cidr := object.get(ipb, "cidr", "")
	is_string(cidr)
	cidr != ""
}

_has_peer_selector(peer) if {
	ps := object.get(peer, "podSelector", null)
	is_object(ps)
}

_has_peer_selector(peer) if {
	ns := object.get(peer, "namespaceSelector", null)
	is_object(ns)
}

deny contains msga if {
	template := input[_]
	template.kind == "SandboxTemplate"

	m := _management(template)
	m != "Managed"

	msga := {
		"alertMessage": sprintf("SandboxTemplate '%v' has networkPolicyManagement set to '%v'; must be 'Managed' or omitted to enforce a policy.", [_name(template), m]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": ["spec.networkPolicyManagement"],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [template]},
	}
}

deny contains msga if {
	template := input[_]
	template.kind == "SandboxTemplate"

	_management(template) == "Managed"

	np := _network_policy(template)
	np == null
	msga := {
		"alertMessage": sprintf("SandboxTemplate '%v' does not define a custom networkPolicy; the Secure Default allows public-internet egress.", [_name(template)]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": ["spec.networkPolicy"],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [template]},
	}
}

deny contains msga if {
	template := input[_]
	template.kind == "SandboxTemplate"

	_management(template) == "Managed"

	np := _network_policy(template)
	np != null
	not is_object(np)

	msga := {
		"alertMessage": sprintf("SandboxTemplate '%v' has a structurally invalid networkPolicy.", [_name(template)]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": ["spec.networkPolicy"],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [template]},
	}
}

deny contains msga if {
	template := input[_]
	template.kind == "SandboxTemplate"

	_management(template) == "Managed"

	np := _network_policy(template)
	is_object(np)

	egress := object.get(np, "egress", null)
	egress != null
	not is_array(egress)

	msga := {
		"alertMessage": sprintf("SandboxTemplate '%v' has a structurally invalid egress block.", [_name(template)]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": ["spec.networkPolicy.egress"],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [template]},
	}
}

deny contains msga if {
	template := input[_]
	template.kind == "SandboxTemplate"

	_management(template) == "Managed"

	np := _network_policy(template)
	is_object(np)

	egress := object.get(np, "egress", [])
	is_array(egress)
	count(egress) > 0

	some rule in egress
	not _egress_rule_scoped(rule)

	msga := {
		"alertMessage": sprintf("SandboxTemplate '%v' has an egress rule without a scoped 'to' selector, which permits traffic to any destination.", [_name(template)]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": ["spec.networkPolicy.egress"],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [template]},
	}
}
