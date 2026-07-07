# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

# CIS 3.2.1 https://workbench.cisecurity.org/sections/1126657/recommendations/1838582
deny contains msga if {
	obj := input[_]
	is_api_server(obj)
	cmd := get_flags(obj.spec.containers[0])
	audit_policy := [command | command := cmd[_]; contains(command, "--audit-policy-file=")]
	count(audit_policy) < 1
	path := append_path(obj.spec.containers[0], 0)

	msga := {
		"alertMessage": "audit logs are not enabled",
		"alertScore": 5,
		"packagename": "armo_builtins",
		"reviewPaths": [path],
		"failedPaths": [path],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [obj]},
	}
}

is_api_server(obj) if {
	obj.apiVersion == "v1"
	obj.kind == "Pod"
	obj.metadata.namespace == "kube-system"
	count(obj.spec.containers) == 1
	count(obj.spec.containers[0].command) > 0
	endswith(obj.spec.containers[0].command[0], "kube-apiserver")
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
