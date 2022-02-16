package armo_builtins


# Fails if workload  has only one replica
deny[msga] {
    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","StatefulSet"}
	spec_template_spec_patterns[wl.kind]
    spec := wl.spec
    result := replicasOneOrLess(spec)
	failedPath := getFailedPath(result)
    fixedPath := getFixedPath(result)

	msga := {
		"alertMessage": sprintf("Workload: %v: %v has only one replica", [ wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": failedPath,
		"fixPaths": fixedPath,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}


replicasOneOrLess(spec) =  [failedPath, fixPath] {
	not spec.replicas
	failedPath = ""
	fixPath = {"path": "spec.replicas", "value": "YOUR_VALUE"}
}

replicasOneOrLess(spec) =  [failedPath, fixPath] {
	spec.replicas == 1
	failedPath = "spec.replicas"
	fixPath = ""
}

 getFailedPath(paths) = [paths[0]] {
	paths[0] != ""
} else = []


getFixedPath(paths) = [paths[1]] {
	paths[1] != ""
} else = []

