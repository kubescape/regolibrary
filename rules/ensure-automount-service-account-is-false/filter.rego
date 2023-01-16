package armo_builtins

deny[msg] {
	obj = input[_]
	obj.kind == "ServiceAccount"
	obj.metadata.name == "default"
	msg := {"alertObject": {"k8sApiObjects": [obj]}}
}

