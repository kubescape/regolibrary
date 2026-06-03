package armo_builtins

import rego.v1

# Fails if workload is Pod
deny contains msga if {
	pod := input[_]
	pod.kind == "Pod"
	not pod.metadata.ownerReferences
	msga := {
		"alertMessage": sprintf("Pod: %v not associated with ReplicaSet or Deployment", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 3,
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [pod]},
	}
}
