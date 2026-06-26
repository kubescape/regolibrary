# regal ignore:directory-package-mismatch 
package armo_builtins

import rego.v1

# Check if --auto-tls is not set to true
deny contains msga if {
	some obj in input
	is_etcd_pod(obj)

	commands := get_flags(obj.spec.containers[0])
	result := invalid_flag(commands)

	msga := {
		"alertMessage": "Auto tls is enabled. Clients are able to use self-signed certificates for TLS.",
		"alertScore": 6,
		"packagename": "armo_builtins",
		"reviewPaths": result.failed_paths,
		"failedPaths": result.failed_paths,
		"fixPaths": result.fix_paths,
		"alertObject": {"k8sApiObjects": [obj]},
	}
}

is_etcd_pod(obj) if {
	obj.apiVersion == "v1"
	obj.kind == "Pod"
	count(obj.spec.containers) == 1
	endswith(split(obj.spec.containers[0].command[0], " ")[0], "etcd")
}

invalid_flag(cmd) := result if {
	contains(cmd[i], "--auto-tls=true")
	fixed = replace(cmd[i], "--auto-tls=true", "--auto-tls=false")
	path := sprintf("spec.containers[0].command[%d]", [i])
	result = {
		"failed_paths": [path],
		"fix_paths": [{"path": path, "value": fixed}],
	}
}

# Combine command and args so flags are detected regardless of where the
# distribution places them. kubeadm puts flags in command; RKE2/k3s keep
# command as ["etcd"] and pass all flags via args.
get_flags(container) := array.concat(container.command, object.get(container, "args", []))
