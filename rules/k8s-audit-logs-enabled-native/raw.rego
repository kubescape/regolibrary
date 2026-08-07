# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

import data.cautils

# Check if audit logs is  enabled for native k8s
deny contains msga if {
	apiserverpod := input[_]
	cmd := get_flags(apiserverpod.spec.containers[0])
	audit_policy := [command | command := cmd[_]; contains(command, "--audit-policy-file=")]
	count(audit_policy) < 1
	path := flags_field(apiserverpod.spec.containers[0])

	msga := {
		"alertMessage": "audit logs is not enabled",
		"alertScore": 9,
		"packagename": "armo_builtins",
		"reviewPaths": [path],
		"failedPaths": [path],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [apiserverpod]},
	}
}

# Combine command and args so flags are detected regardless of where the
# distribution places them. kubeadm puts flags in command; RKE2/k3s keep
# command as ["kube-apiserver"] and pass all flags via args. The comprehension
# over args is null-safe (an explicit `args: null` yields [] rather than erroring).
get_flags(container) := array.concat(container.command, [arg | arg := container.args[_]])

# Bare field (no index) at which the relevant flags live, so an "not set"
# finding on RKE2/k3s points at args rather than command.
flags_field(container) := "spec.containers[0].args" if {
	count([arg | arg := container.args[_]]) > 0
} else := "spec.containers[0].command"
