package armo_builtins
import data.kubernetes.api.client as client
import data

deny[msga] {
	obj := input[_]
	obj.kind == "Service"
	obj.spec.type == "LoadBalancer"
	msga := {"alertObject": {"k8sApiObjects": [obj]}}
}

