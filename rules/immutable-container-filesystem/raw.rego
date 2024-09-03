package armo_builtins


# Fails if pods has container with mutable filesystem
deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
	container := pod.spec.containers[i]
	start_of_path := "spec."
    is_mutable_filesystem(container)
	fixPath = {"path": sprintf("%vcontainers[%d].securityContext.readOnlyRootFilesystem", [start_of_path, i]), "value": "true"}
	msga := {
		"alertMessage": sprintf("container: %v in pod: %v  has  mutable filesystem", [container.name, pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [fixPath],
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}

# Fails if workload has  container with mutable filesystem 
deny[msga] {
    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
    container := wl.spec.template.spec.containers[i]
	start_of_path := "spec.template.spec."
    is_mutable_filesystem(container)
	fixPath = {"path": sprintf("%vcontainers[%d].securityContext.readOnlyRootFilesystem", [start_of_path, i]), "value": "true"}
	msga := {
		"alertMessage": sprintf("container :%v in %v: %v has  mutable filesystem", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [fixPath],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}


# Fails if cronjob has  container with mutable filesystem 
deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
	container = wl.spec.jobTemplate.spec.template.spec.containers[i]
	start_of_path := "spec.jobTemplate.spec.template.spec."
	is_mutable_filesystem(container)
	fixPath = {"path": sprintf("%vcontainers[%d].securityContext.readOnlyRootFilesystem", [start_of_path, i]), "value": "true"}

	msga := {
		"alertMessage": sprintf("container :%v in %v: %v has mutable filesystem", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [fixPath],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

# Default of readOnlyRootFilesystem is false. This field is only in container spec and not pod spec
is_mutable_filesystem(container) {
	container.securityContext.readOnlyRootFilesystem == false
}

is_mutable_filesystem(container) {
	not container.securityContext.readOnlyRootFilesystem == false
    not container.securityContext.readOnlyRootFilesystem == true
}
