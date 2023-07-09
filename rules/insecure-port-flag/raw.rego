package armo_builtins

import data.cautils

# Fails if pod has insecure-port flag enabled
deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
	contains(pod.metadata.name, "kube-apiserver")
    container := pod.spec.containers[i]
	path = is_insecure_port_flag(container, i)
	msga := {
		"alertMessage": sprintf("The API server container: %v has insecure-port flag enabled", [ container.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}

is_insecure_port_flag(container, i) = path {
	command := container.command[j]
	contains(command, "--insecure-port=1")
	path := sprintf("spec.containers[%v].command[%v]", [format_int(i, 10), format_int(j, 10)])
}