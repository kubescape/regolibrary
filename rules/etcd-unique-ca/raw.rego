# regal ignore:directory-package-mismatch 
package armo_builtins

import rego.v1

# CIS 2.7 https://workbench.cisecurity.org/sections/1126654/recommendations/1838578

deny contains msga if {
	etcdPod := [pod | pod := input[_]; filter_input(pod, "etcd")]
	etcdCheckResult := get_argument_value_with_path(get_flags(etcdPod[0].spec.containers[0]), "--trusted-ca-file")

	apiserverPod := [pod | pod := input[_]; filter_input(pod, "kube-apiserver")]
	apiserverCheckResult := get_argument_value_with_path(get_flags(apiserverPod[0].spec.containers[0]), "--client-ca-file")

	etcdCheckResult.value == apiserverCheckResult.value
	msga := {
		"alertMessage": "Cert file is the same both for the api server and the etcd",
		"alertScore": 8,
		"packagename": "armo_builtins",
		"reviewPaths": [etcdCheckResult.path, apiserverCheckResult.path],
		"failedPaths": [etcdCheckResult.path, apiserverCheckResult.path],
		"fixPaths": [etcdCheckResult.fix_paths, apiserverCheckResult.fix_paths],
		"alertObject": {"k8sApiObjects": [etcdPod[0], apiserverPod[0]]},
	}
}

command_api_server_or_etcd(cmd) if {
	endswith(cmd, "kube-apiserver")
}

command_api_server_or_etcd(cmd) if {
	endswith(cmd, "etcd")
}

filter_input(obj, res) if {
	obj.apiVersion == "v1"
	obj.kind == "Pod"
	count(obj.spec.containers) == 1
	endswith(split(obj.spec.containers[0].command[0], " ")[0], res)
}

get_argument_value(command, argument) := value if {
	args := split(command, "=")
	some i, val in args
	val == sprintf("%v", [argument])
	value := args[i + 1]
}

get_argument_value_with_path(cmd, argument) := result if {
	contains(cmd[i], argument)
	argumentValue := get_argument_value(cmd[i], argument)
	path := sprintf("spec.containers[0].command[%d]", [i])
	result = {
		"path": path,
		"value": argumentValue,
		"fix_paths": {"path": path, "value": "<path/to/different-tls-certificate-file.crt>"},
	}
}

# Combine command and args so flags are detected regardless of where the
# distribution places them. kubeadm puts flags in command; RKE2/k3s keep
# command as ["<binary>"] and pass all flags via args.
get_flags(container) := array.concat(container.command, object.get(container, "args", []))
