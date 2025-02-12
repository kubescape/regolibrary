package armo_builtins

import future.keywords.in

deny[msg] {
	obj = input[_]
	is_api_server(obj)
	dontwanted = [
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
		"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
		"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
		"TLS_ECDHE_RSA_WITH_RC4_128_SHA",
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		"TLS_RSA_WITH_AES_128_CBC_SHA",
		"TLS_RSA_WITH_AES_128_CBC_SHA256",
		"TLS_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_RSA_WITH_AES_256_CBC_SHA",
		"TLS_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_RSA_WITH_RC4_128_SHA"
	]

	result = invalid_flag(obj.spec.containers[0].command, dontwanted)
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

is_api_server(obj) {
	obj.apiVersion == "v1"
	obj.kind == "Pod"
	obj.metadata.namespace == "kube-system"
	count(obj.spec.containers) == 1
	count(obj.spec.containers[0].command) > 0
	endswith(obj.spec.containers[0].command[0], "kube-apiserver")
}

get_flag_values(cmd) = {"origin": origin, "values": values} {
	re := " ?--tls-cipher-suites=(.+?)(?: |$)"
	matchs := regex.find_all_string_submatch_n(re, cmd, -1)
	count(matchs) == 1
	values := [val | val := split(matchs[0][1], ",")[j]; val != ""]
	origin := matchs[0][0]
}


# Assume flag set only once
invalid_flag(cmd, dontwanted) = result {
	flag := get_flag_values(cmd[i])

	# value check
	dontuse = [x | x = dontwanted[_]; x in flag.values]
	count(dontuse) > 0


	# get fixed and failed paths
	fixed_values := array.concat(flag.values, dontuse)
	fixed_flag = sprintf("%s=%s", ["--tls-cipher-suites", concat(",", fixed_values)])
	fixed_cmd = replace(cmd[i], flag.origin, fixed_flag)
	path := sprintf("spec.containers[0].command[%d]", [i])


	result := {
		"failed_paths": [path],
		"fix_paths": [{
			"path": path,
			"value": fixed_cmd,
		}],
	}
}

invalid_flag(cmd, wanted) = result {
	full_cmd := concat(" ", cmd)
	not contains(full_cmd, "--tls-cipher-suites")

	path = sprintf("spec.containers[0].command[%d]", [count(cmd)])
	result = {
		"failed_paths": [],
		"fix_paths": [{
			"path": path,
			"value": sprintf("--tls-cipher-suites=%s", [concat(",", wanted)]),
		}],
	}
}
