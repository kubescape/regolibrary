package armo_builtins

deny[msg] {
	obj = input[_]
	filter_input(obj)
	msg := {"alertObject": {"k8sApiObjects": [obj]}}
}

filter_input(obj) {
	obj.apiVersion == "v1"
	obj.kind == "Pod"
	count(obj.spec.containers) == 1
	endswith(split(obj.spec.containers[0].command[0], " ")[0], "etcd")
}
filter_input(obj) {
	obj.apiVersion == "v1"
	obj.kind == "Pod"
	count(obj.spec.containers) == 1
	endswith(split(obj.spec.containers[0].command[0], " ")[0], "kube-apiserver")
}