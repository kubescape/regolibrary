package armo_builtins


# Fails if workload is Pod
deny[msga] {
    wl := input[_]
	wl.kind == "Pod"
	msga := {
		"alertMessage": sprintf("Pod: %v not associated with ReplicaSet or Deployment", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 0,
		"failedPaths": "kind",
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}


