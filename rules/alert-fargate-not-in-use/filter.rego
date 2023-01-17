package armo_builtins

deny[msga] {
	node := input[_]
    node.kind == "Node"

 	msga := {
			"alertMessage": "Consider Fargate for running untrusted workloads",
    		"alertObject": {
               "k8sApiObjects": [node]
            },
			"failedPaths": [],
            "fixPaths":[],
	}
}
