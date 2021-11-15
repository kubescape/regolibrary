package armo_builtins
import data.cautils as cautils

# Fails if pod has insecure-port flag enabled
deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
    container := pod.spec.containers[_]
	isInsecurePortFlag(container)
	msga := {
		"alertMessage": sprintf("The API server container: %v has insecure-port flag enabled", [ container.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}
	
isInsecurePortFlag(container){
    cautils.list_contains(container.command, "--insecure-port=1")
}