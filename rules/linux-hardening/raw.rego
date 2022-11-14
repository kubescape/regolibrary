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
	are_seccomp_and_selinux_disabled(specs)

	# annotation
	annotations := object.get(obj, anotation_path, [])
	app_armor_annotations := [annotations[i] | annotation = i; startswith(i, "container.apparmor.security.beta.kubernetes.io")]
	count(app_armor_annotations) == 0

	# container
	containers_path := array.concat(specs_path, ["containers"])
	containers := object.get(obj, containers_path, [])

	# Psuedo code explanation:
	# for i, container in containers
	#  		if is_unsafe_container:
	# 			fix_paths += [(containers_path[i] + field) for j, field in fix_fields]
	# 
	# At the end we get [[<container1_path1>, <container1_path2>, ...], ...]
	containers_fix_path := concat(".", containers_path)
	fix_fields := ["seccompProfile", "seLinuxOptions", "capabilities.drop[0]"]
	paths := [[{
		"path": sprintf("%s[%d].securityContext.%s", [containers_fix_path, i, field]),
		"value": "YOUR_VALUE",
	} |
		field := fix_fields[j]
	] |
		container = containers[i]
		is_unsafe_container(container)
	]

	count(paths) > 0
}

are_seccomp_and_selinux_disabled(obj) {
	not obj.securityContext.seccompProfile
	not obj.securityContext.seLinuxOptions
}

is_unsafe_container(container) {
	are_seccomp_and_selinux_disabled(container)
	not container.securityContext.capabilities.drop
}
