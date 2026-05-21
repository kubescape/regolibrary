package armo_builtins

import rego.v1

# Check if tls is configured in a etcd service
deny contains msga if {
	obj = input[_]
	is_etcd_pod(obj)

	result = invalid_flag(obj.spec.containers[0].command)

	msga := {
		"alertMessage": "etcd encryption is not enabled",
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

# Assume flag set only once
invalid_flag(cmd) := result if {
	full_cmd = concat(" ", cmd)
	wanted = [
		["--cert-file", "<path/to/tls-certificate-file.crt>"],
		["--key-file", "<path/to/tls-key-file.key>"],
	]

	fix_paths = [{
		"path": sprintf("spec.containers[0].command[%d]", [count(cmd) + i]),
		"value": sprintf("%s=%s", wanted[i]),
	} |
		not contains(full_cmd, wanted[i][0])
	]

	count(fix_paths) > 0

	result = {
		"failed_paths": [],
		"fix_paths": fix_paths,
	}
}
