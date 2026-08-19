# regal ignore:directory-package-mismatch 
package armo_builtins

import rego.v1

# Check if psp is enabled for native k8s
deny contains msga if {
	apiserverpod := input[_]
	flags := get_flags(apiserverpod.spec.containers[0])
	cmd := flags[j]
	contains(cmd, "--authorization-mode=")
	output := split(cmd, "=")
	not contains(output[1], "RBAC")
	path := flag_path(apiserverpod.spec.containers[0], j)

	msga := {
		"alertMessage": "RBAC is not enabled",
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

# Map an index into the combined command+args list back to the real path, so
# findings on RKE2/k3s point at args[j] instead of a non-existent command[i].
flag_path(container, i) := sprintf("spec.containers[0].command[%d]", [i]) if {
	i < count(container.command)
} else := sprintf("spec.containers[0].args[%d]", [i - count(container.command)])
