package armo_builtins

# Check if --auto-tls is not set to true
deny[msga] {
	obj = input[_]
	is_etcd_pod(obj)

	commands := obj.spec.containers[0].command
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

is_etcd_pod(obj) {
	obj.apiVersion == "v1"
	obj.kind == "Pod"
	count(obj.spec.containers) == 1
	endswith(split(obj.spec.containers[0].command[0], " ")[0], "etcd")
}

invalid_flag(cmd) = result {
	contains(cmd[i], "--auto-tls=true")
	fixed = replace(cmd[i], "--auto-tls=true", "--auto-tls=false")
	path := sprintf("spec.containers[0].command[%d]", [i])
	result = {
		"failed_paths": [path],
		"fix_paths": [{"path": path, "value": fixed}],
	}
}
