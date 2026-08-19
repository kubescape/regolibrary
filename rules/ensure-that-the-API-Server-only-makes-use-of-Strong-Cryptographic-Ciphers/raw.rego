# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

deny contains msg if {
	some obj in input
	is_api_server(obj)
	wanted = [
		"TLS_AES_128_GCM_SHA256",
		"TLS_AES_256_GCM_SHA384",
		"TLS_CHACHA20_POLY1305_SHA256",
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
		"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		"TLS_RSA_WITH_AES_128_CBC_SHA",
		"TLS_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_RSA_WITH_AES_256_CBC_SHA",
		"TLS_RSA_WITH_AES_256_GCM_SHA384",
	]
	result = invalid_flag(obj.spec.containers[0], wanted)
	msg := {
		"alertMessage": "The API server is not configured to use strong cryptographic ciphers",
		"alertScore": 2,
		"reviewPaths": result.failed_paths,
		"failedPaths": result.failed_paths,
		"fixPaths": result.fix_paths,
		"packagename": "armo_builtins",
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

get_flag_values(cmd) := {"origin": origin, "values": values} if {
	re := " ?--tls-cipher-suites=(.+?)(?: |$)"
	matchs := regex.find_all_string_submatch_n(re, cmd, -1)
	count(matchs) == 1
	values := [val | val := split(matchs[0][1], ",")[j]; val != ""]
	origin := matchs[0][0]
}

# Assume flag set only once
invalid_flag(container, wanted) := result if {
	cmd := get_flags(container)
	flag := get_flag_values(cmd[i])

	# value check
	missing = [x | x = wanted[_]; not x in flag.values]
	count(missing) > 0

	# get fixed and failed paths
	fixed_values := array.concat(flag.values, missing)
	fixed_flag = sprintf("%s=%s", ["--tls-cipher-suites", concat(",", fixed_values)])
	fixed_cmd = replace(cmd[i], flag.origin, fixed_flag)
	path := flag_path(container, i)

	result := {
		"failed_paths": [path],
		"fix_paths": [{
			"path": path,
			"value": fixed_cmd,
		}],
	}
}

invalid_flag(container, wanted) := result if {
	cmd := get_flags(container)
	full_cmd := concat(" ", cmd)
	not contains(full_cmd, "--tls-cipher-suites")

	path = append_path(container, 0)
	result = {
		"failed_paths": [],
		"fix_paths": [{
			"path": path,
			"value": sprintf("--tls-cipher-suites=%s", [concat(",", wanted)]),
		}],
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

# Path at which to add the k-th missing flag. RKE2/k3s carry flags in args,
# kubeadm in command, so the fix must target whichever array the container uses.
append_path(container, k) := sprintf("spec.containers[0].args[%d]", [count([arg | arg := container.args[_]]) + k]) if {
	count([arg | arg := container.args[_]]) > 0
} else := sprintf("spec.containers[0].command[%d]", [count(container.command) + k])
