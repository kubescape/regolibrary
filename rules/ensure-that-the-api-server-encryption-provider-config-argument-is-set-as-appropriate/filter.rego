package armo_builtins

deny[msg] {
	obj = input[_]
	filter_input(obj)
	msg := {"alertObject": {"k8sApiObjects": [obj]}}
}

filter_input(obj){
	is_api_server(obj)
}
filter_input(obj){
	is_control_plane_info(obj)
}

is_api_server(obj) {
	obj.apiVersion == "v1"
	obj.kind == "Pod"
	obj.metadata.namespace == "kube-system"
	count(obj.spec.containers) == 1
	count(obj.spec.containers[0].command) > 0
	endswith(obj.spec.containers[0].command[0], "kube-apiserver")
}

is_control_plane_info(obj) {
	obj.apiVersion == "hostdata.kubescape.cloud/v1beta0"
	obj.kind == "ControlPlaneInfo"
}
