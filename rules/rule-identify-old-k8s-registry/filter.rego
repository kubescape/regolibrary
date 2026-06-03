package armo_builtins

import rego.v1

deny contains msg if {
	# find aggregated API APIServices
	obj = input[_]
	obj.metadata.namespace == "kube-system"
	msg := {"alertObject": {"k8sApiObjects": [obj]}}
}
