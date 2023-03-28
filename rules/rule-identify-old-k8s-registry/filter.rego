package armo_builtins

import future.keywords.in

deny[msg] {
	# find aggregated API APIServices
	obj = input[_]
	obj.metadata.namespace == "kube-system"
	msg := {
		"alertObject": {"k8sApiObjects": [obj]},
	}
}

