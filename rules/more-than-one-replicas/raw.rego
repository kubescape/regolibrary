package armo_builtins


# Fails if workload doas not have replicas more than one
deny[msga] {
    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","StatefulSet"}
	spec_template_spec_patterns[wl.kind]
    spec := wl.spec
    replicasOneOrLess(spec)
	msga := {
		"alertMessage": sprintf("Workload: %v: %v   doas not have replicas more than one", [ wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}


replicasOneOrLess(spec){
	not spec.replicas
}

replicasOneOrLess(spec){
	spec.replicas == 1
}
