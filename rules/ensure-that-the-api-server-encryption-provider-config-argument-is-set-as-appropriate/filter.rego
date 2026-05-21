package armo_builtins

import rego.v1

deny contains msg if {
	obj = input[_]
	filter_input(obj)
	msg := {"alertObject": {"k8sApiObjects": [obj]}}
}

filter_input(obj) if {
	is_api_server(obj)
}

filter_input(obj) if {
	is_control_plane_info(obj)
}

is_api_server(obj) if {
	obj.apiVersion == "v1"
	obj.kind == "Pod"
	obj.metadata.namespace == "kube-system"
	count(obj.spec.containers) == 1
	count(obj.spec.containers[0].command) > 0
	endswith(obj.spec.containers[0].command[0], "kube-apiserver")
}

is_control_plane_info(obj) if {
	obj.apiVersion == "hostdata.kubescape.cloud/v1beta0"
	obj.kind == "ControlPlaneInfo"
}
