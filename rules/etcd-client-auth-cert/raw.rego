# regal ignore:directory-package-mismatch 
package armo_builtins

import rego.v1

# Check if --client-cert-auth is set to true
deny contains msga if {
	some obj in input
	is_etcd_pod(obj)
	result = invalid_flag(get_flags(obj.spec.containers[0]))

	msga := {
		"alertMessage": "Etcd server is not requiring a valid client certificate",
		"alertScore": 8,
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

# Combine command and args so flags are detected regardless of where the
# distribution places them. kubeadm puts flags in command; RKE2/k3s keep
# command as ["etcd"] and pass all flags via args.
get_flags(container) := array.concat(container.command, object.get(container, "args", []))

# Assume flag set only once
invalid_flag(cmd) := result if {
	full_cmd = concat(" ", cmd)
	not contains(full_cmd, "--client-cert-auth")
	result := {
		"failed_paths": [],
		"fix_paths": [{
			"path": sprintf("spec.containers[0].command[%d]", [count(cmd)]),
			"value": "--client-cert-auth=true",
		}],
	}
}

invalid_flag(cmd) := result if {
	contains(cmd[i], "--client-cert-auth=false")
	fixed = replace(cmd[i], "--client-cert-auth=false", "--client-cert-auth=true")
	path := sprintf("spec.containers[0].command[%d]", [i])
	result = {
		"failed_paths": [path],
		"fix_paths": [{"path": path, "value": fixed}],
	}
}
