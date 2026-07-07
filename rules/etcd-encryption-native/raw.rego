# regal ignore:directory-package-mismatch 
package armo_builtins

import rego.v1

import data.cautils

# Check if encryption in etcd is enabled for native k8s
deny contains msga if {
	apiserverpod := input[_]
	cmd := get_flags(apiserverpod.spec.containers[0])
	enc_command := [command | command := cmd[_]; contains(command, "--encryption-provider-config=")]
	count(enc_command) < 1
	fixpath := {"path": append_path(apiserverpod.spec.containers[0], 0), "value": "--encryption-provider-config=YOUR_VALUE"}

	msga := {
		"alertMessage": "etcd encryption is not enabled",
		"alertScore": 9,
		"packagename": "armo_builtins",
		"failedPaths": [],
		"fixPaths": [fixpath],
		"alertObject": {"k8sApiObjects": [apiserverpod]},
	}
}

# Combine command and args so flags are detected regardless of where the
# distribution places them. kubeadm puts flags in command; RKE2/k3s keep
# command as ["kube-apiserver"] and pass all flags via args.
get_flags(container) := array.concat(container.command, [arg | arg := container.args[_]])

# Path at which to add the k-th missing flag. RKE2/k3s carry flags in args,
# kubeadm in command, so the fix must target whichever array the container uses.
append_path(container, k) := sprintf("spec.containers[0].args[%d]", [count([arg | arg := container.args[_]]) + k]) if {
	count([arg | arg := container.args[_]]) > 0
} else := sprintf("spec.containers[0].command[%d]", [count(container.command) + k])
