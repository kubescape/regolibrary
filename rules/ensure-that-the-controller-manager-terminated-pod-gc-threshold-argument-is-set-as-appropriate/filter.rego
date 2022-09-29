package armo_builtins

deny[msg] {
	obj = input[_]
	is_controller_manager(obj)
	msg := {"alertObject": {"k8sApiObjects": [obj]}}
}

is_controller_manager(obj) {
	obj.apiVersion == "v1"
	obj.kind == "Pod"
	obj.metadata.namespace == "kube-system"
	count(obj.spec.containers) == 1
	count(obj.spec.containers[0].command) > 0
	endswith(obj.spec.containers[0].command[0], "kube-controller-manager")
}
