package armo_builtins
import data.kubernetes.api.client as client
import data

deny[msg] {
	obj := input[_]
	obj.kind == "Service"
	obj.spec.type == "LoadBalancer"
	msg := {"alertObject": {"k8sApiObjects": [obj]}}
}

