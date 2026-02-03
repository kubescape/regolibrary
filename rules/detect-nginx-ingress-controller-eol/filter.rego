package armo_builtins

# Filter returns only the workload resources that could potentially fail this rule
# This is used by Kubescape to calculate the risk score accurately
# We only check Deployments, DaemonSets, and StatefulSets
deny[msga] {
	workload := input[_]
	workload.kind == "Deployment"
	msga := {
		"alertMessage": "",
		"alertObject": {
			"k8sApiObjects": [workload]
		}
	}
}

deny[msga] {
	workload := input[_]
	workload.kind == "DaemonSet"
	msga := {
		"alertMessage": "",
		"alertObject": {
			"k8sApiObjects": [workload]
		}
	}
}

deny[msga] {
	workload := input[_]
	workload.kind == "StatefulSet"
	msga := {
		"alertMessage": "",
		"alertObject": {
			"k8sApiObjects": [workload]
		}
	}
}
