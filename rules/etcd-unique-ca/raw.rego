package armo_builtins

import future.keywords.in

deny[msga] {
	etcdPod := [pod | pod := input[_]; filter_input(pod, "etcd")]
	etcdCheckResult := get_argument_value_with_path(etcdPod[0].spec.containers[0].command, "--trusted-ca-file")

	apiserverPod := [pod | pod := input[_]; filter_input(pod, "kube-apiserver")]
	apiserverCheckResult := get_argument_value_with_path(apiserverPod[0].spec.containers[0].command, "--client-ca-file")

	etcdCheckResult.value == apiserverCheckResult.value
	msga := {
		"alertMessage": "Cert file is the same both for the api server and the etcd",
		"alertScore": 8,
		"packagename": "armo_builtins",
		"failedPaths": [etcdCheckResult.path, apiserverCheckResult.path],
		"fixPaths": [etcdCheckResult.fix_paths, apiserverCheckResult.fix_paths],
		"alertObject": {"k8sApiObjects": [etcdPod[0], apiserverPod[0]]},
	}
}

filter_input(obj, res) {
	obj.apiVersion == "v1"
	obj.kind == "Pod"
	count(obj.spec.containers) == 1
	endswith(split(obj.spec.containers[0].command[0], " ")[0], res)
}

get_argument_value(command, argument) = value {
	args := regex.split("=", command)

	some i, sprintf("%v", [argument]) in args
	value := args[i + 1]
}

get_argument_value_with_path(cmd, argument) = result {
	contains(cmd[i], argument)
	argumentValue := get_argument_value(cmd[i], argument)

	path := sprintf("spec.containers[0].command[%d]", [i])
	result = {
		"path": path,
		"value": argumentValue,
		"fix_paths": {"path": path, "value": "<path/to/different-tls-certificate-file.crt>"},
	}
}
