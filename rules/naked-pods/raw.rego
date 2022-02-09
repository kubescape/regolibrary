package armo_builtins


# Fails if workload is Pod
deny[msga] {
    pod := input[_]
	pod.kind == "Pod"
	not pod.metadata.ownerReferences
	msga := {
		"alertMessage": sprintf("Pod: %v not associated with ReplicaSet or Deployment", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 3,
		"failedPaths": [],
		"fixPaths": [{"path": "metadata.ownerReferences", "value": "YOUR_VALUE"}],
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}


