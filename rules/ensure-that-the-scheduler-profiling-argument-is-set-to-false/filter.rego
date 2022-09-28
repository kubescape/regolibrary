package armo_builtins

deny[msg] {
	obj = input[_]
	filter_input(obj)
	msg := {"alertObject": {"k8sApiObjects": [obj]}}
}

filter_input(obj) {
	obj.apiVersion == "v1"
	obj.kind == "Pod"
	obj.metadata.namespace == "kube-system"
	count(obj.spec.containers) == 1
	count(obj.spec.containers[0].command) > 0
	endswith(obj.spec.containers[0].command[0], "kube-scheduler")
}
