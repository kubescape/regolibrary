package armo_builtins



deny[msga] {
    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet", "Job", "CronJob", "Pod"}
	spec_template_spec_patterns[wl.kind]
	result := isDefaultNamespace(wl.metadata)
	failedPath := getFailedPath(result)
    fixedPath := getFixedPath(result)
	msga := {
		"alertMessage": sprintf("%v: %v has pods running in the 'default' namespace", [wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 3,
		"failedPaths": failedPath,
		"fixPaths": fixedPath,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}



isDefaultNamespace(metadata) = [failedPath, fixPath] {
	metadata.namespace == "default"
	failedPath = "metadata.namespace"
	fixPath = "" 
}


isDefaultNamespace(metadata) = [failedPath, fixPath] {
	not metadata.namespace 
	fixPath = {"path": "metadata.namespace", "value": "YOUR_VALUE"} 
	failedPath = "" 
}

getFailedPath(paths) = [paths[0]] {
	paths[0] != ""
} else = []


getFixedPath(paths) = [paths[1]] {
	paths[1] != ""
} else = []


