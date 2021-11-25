package armo_builtins


# Fails if pods has container with mutable filesystem
deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
	container := pod.spec.containers[i]
	begginingOfPath := "spec."
    result := isMutableFilesystem(container, begginingOfPath, i)
	msga := {
		"alertMessage": sprintf("container: %v in pod: %v  has  mutable filesystem", [container.name, pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [result],
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
	begginingOfPath := "spec.template.spec."
    result := isMutableFilesystem(container, begginingOfPath, i)
	msga := {
		"alertMessage": sprintf("container :%v in %v: %v has  mutable filesystem", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [result],
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
	begginingOfPath := "spec.jobTemplate.spec.template.spec."
	result := isMutableFilesystem(container, begginingOfPath, i)
	msga := {
		"alertMessage": sprintf("container :%v in %v: %v has mutable filesystem", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [result],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

# Default of readOnlyRootFilesystem is false. This field is only in container spec and not pod spec
isMutableFilesystem(container, begginingOfPath, i) = path {
    container.securityContext.readOnlyRootFilesystem == false
	path = sprintf("%vcontainers[%v].securityContext.readOnlyRootFilesystem", [begginingOfPath, format_int(i, 10)])
 }

 isMutableFilesystem(container, begginingOfPath, i) = path{
	 not container.securityContext.readOnlyRootFilesystem == false
     not container.securityContext.readOnlyRootFilesystem == true
	 path = ""
 }