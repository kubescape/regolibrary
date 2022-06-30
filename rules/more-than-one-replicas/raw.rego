package armo_builtins


# Fails if workload  has only one replica
deny[msga] {
    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","StatefulSet"}
	spec_template_spec_patterns[wl.kind]
    spec := wl.spec
    result := replicas_one_or_less(spec)
	failed_path := get_failed_path(result)
    fixed_path := get_fixed_path(result)

	msga := {
		"alertMessage": sprintf("Workload: %v: %v has only one replica", [ wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": failed_path,
		"fixPaths": fixed_path,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}


replicas_one_or_less(spec) =  [failed_path, fixPath] {
	not spec.replicas
	failed_path = ""
	fixPath = {"path": "spec.replicas", "value": "YOUR_VALUE"}
}

replicas_one_or_less(spec) =  [failed_path, fixPath] {
	spec.replicas == 1
	failed_path = "spec.replicas"
	fixPath = ""
}

 get_failed_path(paths) = [paths[0]] {
	paths[0] != ""
} else = []


get_fixed_path(paths) = [paths[1]] {
	paths[1] != ""
} else = []

