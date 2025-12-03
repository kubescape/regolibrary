package armo_builtins

import future.keywords.in

# Fails if pod does not define linux security hardening 
deny[msga] {
	obj := input[_]
	fix_paths := is_unsafe_obj(obj)
	count(fix_paths) > 0

	# final_fix_pathes := array.concat(fix_paths) # -> produce only one failed result
	final_fix_pathes := fix_paths[_] # -> produce failed result for each container
	msga := {
		"alertMessage": sprintf("%s: %s does not define any linux security hardening", [obj.kind, obj.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": final_fix_pathes,
		"alertObject": {"k8sApiObjects": [obj]},
	}
}

is_unsafe_obj(obj) := fix_paths {
	obj.kind == "Pod"
	fix_paths := are_unsafe_specs(obj, ["spec"], ["metadata", "annotations"])
} else := fix_paths {
	obj.kind == "CronJob"
	fix_paths := are_unsafe_specs(obj, ["spec", "jobTemplate", "spec", "template", "spec"], ["spec", "jobTemplate", "spec", "template", "metadata", "annotations"])
} else := fix_paths {
	obj.kind in ["Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"]
	fix_paths := are_unsafe_specs(obj, ["spec", "template", "spec"], ["spec", "template", "metadata", "annotations"])
}

are_unsafe_specs(obj, specs_path, anotation_path) := paths {
	# spec
	specs := object.get(obj, specs_path, null)
	specs != null

	# annotation
	annotations := object.get(obj, anotation_path, [])
	app_armor_annotations := [annotations[i] | annotation = i; startswith(i, "container.apparmor.security.beta.kubernetes.io")]
	pod_has_apparmor := count(app_armor_annotations) > 0

	# Check both regular containers and initContainers
	fix_fields := ["seccompProfile", "seLinuxOptions", "capabilities.drop[0]"]
	
	# Regular containers
	containers_path := array.concat(specs_path, ["containers"])
	containers := object.get(obj, containers_path, [])
	containers_fix_path := concat(".", containers_path)
	container_paths := [[{
		"path": sprintf("%s[%d].securityContext.%s", [containers_fix_path, i, field]),
		"value": "YOUR_VALUE",
	} |
		field := fix_fields[j]
	] |
		container = containers[i]
		is_unsafe_container(specs, container, pod_has_apparmor)
	]

	# Init containers
	init_containers_path := array.concat(specs_path, ["initContainers"])
	init_containers := object.get(obj, init_containers_path, [])
	init_containers_fix_path := concat(".", init_containers_path)
	init_container_paths := [[{
		"path": sprintf("%s[%d].securityContext.%s", [init_containers_fix_path, i, field]),
		"value": "YOUR_VALUE",
	} |
		field := fix_fields[j]
	] |
		init_container = init_containers[i]
		is_unsafe_container(specs, init_container, pod_has_apparmor)
	]

	# Combine both sets of paths
	paths := array.concat(container_paths, init_container_paths)
	count(paths) > 0
}

are_seccomp_and_selinux_disabled(obj) {
	not obj.securityContext.seccompProfile
	not obj.securityContext.seLinuxOptions
}

# A container is unsafe if it has NO hardening mechanisms at all
# Considering both pod-level and container-level settings
is_unsafe_container(pod_spec, container, pod_has_apparmor) {
	# Container is unsafe if it has NONE of these protections:
	# - No seccomp at pod or container level
	not pod_spec.securityContext.seccompProfile
	not container.securityContext.seccompProfile
	
	# - No selinux at pod or container level
	not pod_spec.securityContext.seLinuxOptions
	not container.securityContext.seLinuxOptions
	
	# - No apparmor at pod level
	not pod_has_apparmor
	
	# - No capabilities at container level
	not container.securityContext.capabilities.drop
}
