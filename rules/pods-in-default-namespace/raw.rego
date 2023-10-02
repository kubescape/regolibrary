package armo_builtins

deny[msga] {
    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet", "Job", "CronJob", "Pod"}
	spec_template_spec_patterns[wl.kind]
	result := is_default_namespace(wl.metadata)
	failed_path := get_failed_path(result)
    fixed_path := get_fixed_path(result)
	msga := {
		"alertMessage": sprintf("%v: %v has pods running in the 'default' namespace", [wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 3,
		"reviewPaths": failed_path,
		"failedPaths": failed_path,
		"fixPaths": fixed_path,
		"alertObject": {
			"k8sApiObjects": [wl]
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


