package armo_builtins

deny[msga] {
    resource := input[_]
	not is_kubernetes_default_resource(resource)
	result := is_default_namespace(resource.metadata)
	failed_path := get_failed_path(result)
    fixed_path := get_fixed_path(result)
	msga := {
		"alertMessage": sprintf("%v: %v is in the 'default' namespace", [resource.kind, resource.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 3,
		"reviewPaths": failed_path,
		"failedPaths": failed_path,
		"fixPaths": fixed_path,
		"alertObject": {
			"k8sApiObjects": [resource]
		}
	}
}

is_default_namespace(metadata) = [failed_path, fixPath] {
	metadata.namespace == "default"
	failed_path = "metadata.namespace"
	fixPath = "" 
}

is_default_namespace(metadata) = [failed_path, fixPath] {
	not metadata.namespace
	failed_path = ""
	fixPath = {"path": "metadata.namespace", "value": "YOUR_NAMESPACE"}
}

get_failed_path(paths) = [paths[0]] {
	paths[0] != ""
} else = []

get_fixed_path(paths) = [paths[1]] {
	paths[1] != ""
} else = []

# EndpointSlices backing the kubernetes Service are controller-managed in the
# default namespace for API server discovery and are excluded by the CIS
# benchmark (CIS 5.7.4: kubescape/regolibrary#644). Match by the
# kubernetes.io/service-name label since slice names may carry a hash suffix,
# and require the controller's endpointslice.kubernetes.io/managed-by label to avoid
# spoofed user resources.
is_kubernetes_default_resource(resource) {
	resource.kind == "EndpointSlice"
	resource.metadata.namespace == "default"
	resource.metadata.labels["kubernetes.io/service-name"] == "kubernetes"
	resource.metadata.labels["endpointslice.kubernetes.io/managed-by"] == "endpointslice-controller.k8s.io"
}
