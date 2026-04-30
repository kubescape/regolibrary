package armo_builtins

# Filter to identify kube-proxy ConfigMap in kube-system namespace
deny[msga] {
	configmap := input[_]
	configmap.kind == "ConfigMap"
	configmap.metadata.name == "kube-proxy"
	configmap.metadata.namespace == "kube-system"
	
	msga := {
		"alertMessage": "",
		"packagename": "armo_builtins",
		"alertObject": {"k8sApiObjects": [configmap]},
	}
}
