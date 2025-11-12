package armo_builtins

_deny_supplemental_groups_msg(kind_label, obj, groups, path) = msga {
	groups[_] == 0

	msga := {
		"alertMessage": sprintf("%s: %v uses disallowed supplemental group '0'", [kind_label, obj.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
		"fixPaths": [{"path": path, "value": "REMOVE_GROUP_0"}],
		"alertObject": {"k8sApiObjects": [obj]},
	}
}

### POD ###

# Fails if securityContext.supplementalGroups contains the root group (0)
deny[msga] {
	# verify the object kind
	pod := input[_]
	pod.kind == "Pod"

	groups := pod.spec.securityContext.supplementalGroups
	path := "spec.securityContext.supplementalGroups"
	msga := _deny_supplemental_groups_msg("Pod", pod, groups, path)
}

### WORKLOAD ###

# Fails if securityContext.supplementalGroups contains the root group (0)
deny[msga] {
	# verify the object kind
	wl := input[_]
	manifest_kind := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	manifest_kind[wl.kind]

	groups := wl.spec.template.spec.securityContext.supplementalGroups
	path := "spec.template.spec.securityContext.supplementalGroups"
	msga := _deny_supplemental_groups_msg("Workload", wl, groups, path)
}

### CRONJOB ###

# Fails if securityContext.supplementalGroups contains the root group (0)
deny[msga] {
	# verify the object kind
	cj := input[_]
	cj.kind == "CronJob"

	groups := cj.spec.jobTemplate.spec.template.spec.securityContext.supplementalGroups
	path := "spec.jobTemplate.spec.template.spec.securityContext.supplementalGroups"
	msga := _deny_supplemental_groups_msg("CronJob", cj, groups, path)
}
