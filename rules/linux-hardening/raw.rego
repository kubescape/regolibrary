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
	fix_paths := are_unsafe_specs(obj, ["spec"])
} else := fix_paths {
	obj.kind == "CronJob"
	fix_paths := are_unsafe_specs(obj, ["spec", "jobTemplate", "spec", "template", "spec"])
} else := fix_paths {
	obj.kind in ["Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"]
	fix_paths := are_unsafe_specs(obj, ["spec", "template", "spec"])
}

are_unsafe_specs(obj, specs_path) := paths {
	# spec
	specs := object.get(obj, specs_path, null)
	specs != null

	# Check both regular containers and initContainers
	fix_fields := ["seccompProfile"]

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
		is_unsafe_container(specs, container)
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
		is_unsafe_container(specs, init_container)
	]

	# Combine both sets of paths
	paths := array.concat(container_paths, init_container_paths)
	count(paths) > 0
}

# A container is unsafe if it has no seccomp profile defined
# at either pod level or container level
is_unsafe_container(pod_spec, container) {
	not pod_spec.securityContext.seccompProfile
	not container.securityContext.seccompProfile
}
