package armo_builtins
import data.cautils as cautils

# Fails if pod has insecure-port flag enabled
deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
	contains(pod.metadata.name, "kube-apiserver")
    container := pod.spec.containers[_]
	msga := {
		"alertMessage": sprintf("The API server container: %v has insecure-port flag enabled", [ container.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [""],
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}
