# regal ignore:directory-package-mismatch 
package armo_builtins

import rego.v1

# Check if --auto-tls is not set to true
deny contains msga if {
	some obj in input
	is_etcd_pod(obj)
	result := invalid_flag(obj.spec.containers[0])

	msga := {
		"alertMessage": "Peer auto tls is enabled. Peer clients are able to use self-signed certificates for TLS.",
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

# A repeated boolean flag takes its value from the last occurrence in
# command + args.
last_flag_index(flags) := max({i |
	some i, arg in flags
	split(arg, "=")[0] == "--peer-auto-tls"
})

invalid_flag(container) := result if {
	flags := get_flags(container)
	i := last_flag_index(flags)

	# A bare boolean flag means true, and the flag parser also accepts the
	# true spellings of strconv.ParseBool.
	suffix := trim_prefix(flags[i], "--peer-auto-tls")
	suffix in {"", "=1", "=t", "=T", "=true", "=TRUE", "=True"}
	path := flag_path(container, i)
	result := {
		"failed_paths": [path],
		"fix_paths": [{"path": path, "value": "--peer-auto-tls=false"}],
	}
}

# Combine command and args so flags are detected regardless of where the
# distribution places them. kubeadm puts flags in command; RKE2/k3s keep
# command as ["etcd"] and pass all flags via args.
get_flags(container) := array.concat(container.command, [arg | arg := container.args[_]])

# Map an index into the combined command+args list back to the real path, so
# findings on RKE2/k3s point at args[j] instead of a non-existent command[i].
flag_path(container, i) := sprintf("spec.containers[0].command[%d]", [i]) if {
	i < count(container.command)
} else := sprintf("spec.containers[0].args[%d]", [i - count(container.command)])
