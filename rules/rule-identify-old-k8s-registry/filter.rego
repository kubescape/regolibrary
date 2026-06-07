# regal ignore:directory-package-mismatch  
package armo_builtins

import rego.v1

deny contains msg if {
	# find aggregated API APIServices
	some obj in input
	obj.metadata.namespace == "kube-system"
	msg := {"alertObject": {"k8sApiObjects": [obj]}}
}
