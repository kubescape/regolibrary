package armo_builtins

deny[msga] {
    resource := input[_]
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


