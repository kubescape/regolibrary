# regal ignore:directory-package-mismatch 
package armo_builtins

import rego.v1

# Check if peer tls is enabled in etcd cluster
deny contains msga if {
	some obj in input
	is_etcd_pod(obj)
	result = invalid_flag(get_flags(obj.spec.containers[0]))

	msga := {
		"alertMessage": "Etcd encryption for peer connection is not enabled.",
		"alertScore": 7,
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
	wanted = [
		["--peer-cert-file", "<path/to/tls-certificate-file.crt>"],
		["--peer-key-file", "<path/to/tls-key-file.key>"],
	]

	fix_paths = [{
		"path": sprintf("spec.containers[0].command[%d]", [count(cmd) + i]),
		"value": sprintf("%s=%s", wanted[i]),
	} |
		not contains(full_cmd, wanted[i][0])
	]

	count(fix_paths) > 0

	result = {
		"failed_paths": ["spec.containers[0].command"],
		"fix_paths": fix_paths,
	}
}
