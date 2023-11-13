package armo_builtins


# Fails if pods has container with mutable filesystem
deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
	container := pod.spec.containers[i]
	start_of_path := "spec."
    result := is_mutable_filesystem(container, start_of_path, i)
	failed_path := get_failed_path(result)
    fixed_path := get_fixed_path(result)
	msga := {
		"alertMessage": sprintf("container: %v in pod: %v  has  mutable filesystem", [container.name, pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": failed_path,
		"fixPaths": fixed_path,
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
    result := is_mutable_filesystem(container, start_of_path, i)
	failed_path := get_failed_path(result)
    fixed_path := get_fixed_path(result)
	msga := {
		"alertMessage": sprintf("container :%v in %v: %v has  mutable filesystem", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": failed_path,
		"fixPaths": fixed_path,
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
	result := is_mutable_filesystem(container, start_of_path, i)
	failed_path := get_failed_path(result)
    fixed_path := get_fixed_path(result)

	msga := {
		"alertMessage": sprintf("container :%v in %v: %v has mutable filesystem", [container.name, wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": failed_path,
		"fixPaths": fixed_path,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}

# Default of readOnlyRootFilesystem is false. This field is only in container spec and not pod spec
is_mutable_filesystem(container, start_of_path, i) = [failed_path, fixPath]  {
	container.securityContext.readOnlyRootFilesystem == false
	fixPath = {"path": sprintf("%vcontainers[%v].securityContext.readOnlyRootFilesystem", [start_of_path, format_int(i, 10)]), "value": "true"}
	failed_path = ""
 }

 is_mutable_filesystem(container, start_of_path, i)  = [failed_path, fixPath] {
	not container.securityContext.readOnlyRootFilesystem == false
    not container.securityContext.readOnlyRootFilesystem == true
	fixPath = {"path": sprintf("%vcontainers[%v].securityContext.readOnlyRootFilesystem", [start_of_path, format_int(i, 10)]), "value": "true"}
	failed_path = ""
 }


 get_failed_path(paths) = [paths[0]] {
	paths[0] != ""
} else = []


get_fixed_path(paths) = [paths[1]] {
	paths[1] != ""
} else = []
