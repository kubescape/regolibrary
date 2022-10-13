package armo_builtins

# Fails if pod does not define seccompProfile as RuntimeDefault
deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
    wl_spec := pod.spec
	beggining_of_path := "spec"
    container := pod.spec.containers[i]

	seccompProfile_result := get_seccompProfile_definition(wl_spec, container, i, beggining_of_path)
	seccompProfile_result.failed == true

	msga := {
		"alertMessage": sprintf("Pod: %v does not define seccompProfile as RuntimeDefault", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": seccompProfile_result.failed_path,
		"fixPaths": seccompProfile_result.fix_path,
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}

# Fails if workload does not define seccompProfile as RuntimeDefault
deny[msga] {
    wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
    wl_spec := wl.spec.template.spec
	beggining_of_path := "spec.template.spec"
    container := wl.spec.template.spec.containers[i]

	seccompProfile_result := get_seccompProfile_definition(wl_spec, container, i, beggining_of_path)
	seccompProfile_result.failed == true

	fixPaths := [{"path": sprintf("spec.template.spec.containers[%v].securityContext.seccompProfile.type", [format_int(i, 10)]), "value": "RuntimeDefault"}]

	msga := {
		"alertMessage": sprintf("Workload: %v does not define seccompProfile as RuntimeDefault", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": seccompProfile_result.failed_path,
		"fixPaths": seccompProfile_result.fix_path,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}


# Fails if CronJob does not define seccompProfile as RuntimeDefault
deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"
    wl_spec := wl.spec.jobTemplate.spec.template.spec
	beggining_of_path := "spec.jobTemplate.spec.template.spec"
	container = wl.spec.jobTemplate.spec.template.spec.containers[i]

	seccompProfile_result := get_seccompProfile_definition(wl_spec, container, i, beggining_of_path)
	seccompProfile_result.failed == true

	msga := {
		"alertMessage": sprintf("Cronjob: %v does not define seccompProfile as RuntimeDefault", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": seccompProfile_result.failed_path,
		"fixPaths": seccompProfile_result.fix_path,
		"alertObject": {
			"k8sApiObjects": [wl]
		}
	}
}


# container definition takes precedence
get_seccompProfile_definition(wl, container, i, beggining_of_path) = seccompProfile_result {
	container.securityContext.seccompProfile.type == "RuntimeDefault"
    seccompProfile_result := {"failed": false, "failed_path": [], "fix_path": []}

} else = seccompProfile_result {
	container.securityContext.seccompProfile.type != "RuntimeDefault"
    failed_path := sprintf("%v.containers[%v].securityContext.seccompProfile.type", [beggining_of_path, format_int(i, 10)])
    seccompProfile_result := {"failed": true, "failed_path": [failed_path], "fix_path": []}

} else = seccompProfile_result {
	wl.securityContext.seccompProfile.type == "RuntimeDefault" 
    seccompProfile_result := {"failed": false,  "failed_path": [], "fix_path": []}

} else = seccompProfile_result {
	wl.securityContext.seccompProfile.type != "RuntimeDefault" 
	failed_path := sprintf("%v.securityContext.seccompProfile.type", [beggining_of_path])
    seccompProfile_result := {"failed": true,  "failed_path": [failed_path], "fix_path": []}

} else = seccompProfile_result{
	fix_path := [{"path": sprintf("%v.containers[%v].securityContext.seccompProfile.type", [beggining_of_path,format_int(i, 10)]), "value":"RuntimeDefault"}]
	seccompProfile_result := {"failed": true, "failed_path": [], "fix_path": fix_path}
}
