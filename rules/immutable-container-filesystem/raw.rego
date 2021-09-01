package armo_builtins


# Fails if pods has container with mutable filesystem
deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
	container := pod.spec.containers[_]
    isMutableFilesystem(container)
	msga := {
		"alertMessage": sprintf("container: %v in pod: %v  has  mutable filesystem", [container.name, pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
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
    container := wl.spec.template.spec.containers[_]
    isMutableFilesystem(container)
	msga := {
		"alertMessage": sprintf("container :%v in %v: %v has  mutable filesystem", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}


# Fails if cronjob has  container with mutable filesystem 
deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
	container = wl.spec.jobTemplate.spec.template.spec.containers[_]
	isMutableFilesystem(container)
	msga := {
		"alertMessage": sprintf("container :%v in %v: %v has mutable filesystem", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

# Default of readOnlyRootFilesystem is false. This field is only in container spec and not pod spec
isMutableFilesystem(container){
     not container.securityContext.readOnlyRootFilesystem
 }