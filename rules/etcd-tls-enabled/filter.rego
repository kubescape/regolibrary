package armo_builtins

import rego.v1

deny contains msg if {
	obj = input[_]
	is_etcd_pod(obj)
	msg := {"alertObject": {"k8sApiObjects": [obj]}}
}

is_etcd_pod(obj) if {
	obj.apiVersion == "v1"
	obj.kind == "Pod"
	count(obj.spec.containers) == 1
	endswith(split(obj.spec.containers[0].command[0], " ")[0], "etcd")
}
