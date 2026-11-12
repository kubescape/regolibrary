# regal ignore:directory-package-mismatch  
package armo_builtins

import rego.v1

deny contains msga if {
	resource := input[_]
	volumes_path := get_volumes_path(resource)
	volumes := object.get(resource, volumes_path, [])
	volume := volumes[i]
	volume.persistentVolumeClaim

	PVC := input[_]
	PVC.kind == "PersistentVolumeClaim"
	PVC.metadata.name == volume.persistentVolumeClaim.claimName
	is_same_namespace(PVC.metadata, resource.metadata)

	containers_path := get_containers_paths(resource)[_]
	containers := object.get(resource, containers_path, [])
	container := containers[j]

	# check if volume is mounted
	container.volumeMounts[k].name == volume.name

	failedPaths := sprintf("%s[%d].volumeMounts[%d]", [concat(".", containers_path), j, k])

	msga := {
		"alertMessage": sprintf("%v: %v has mounted PVC", [resource.kind, resource.metadata.name]),
		"packagename": "armo_builtins",
		"deletePaths": [failedPaths],
		"failedPaths": [failedPaths],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [resource]},
		"relatedObjects": [{"object": PVC}],
	}
}

# get_containers_paths - get resource container array paths for  {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
get_containers_paths(resource) := result if {
	resource_kinds := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	resource_kinds[resource.kind]
	result = {
		["spec", "template", "spec", "containers"],
		["spec", "template", "spec", "initContainers"],
	}
}

# get_containers_paths - get resource container array paths for "Pod"
get_containers_paths(resource) := result if {
	resource.kind == "Pod"
	result = {
		["spec", "containers"],
		["spec", "initContainers"],
		["spec", "ephemeralContainers"],
	}
}

# get_containers_paths - get resource container array paths for  "CronJob"
get_containers_paths(resource) := result if {
	resource.kind == "CronJob"
	result = {
		["spec", "jobTemplate", "spec", "template", "spec", "containers"],
		["spec", "jobTemplate", "spec", "template", "spec", "initContainers"],
	}
}

# get_volume_path - get resource volumes paths for {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
get_volumes_path(resource) := result if {
	resource_kinds := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	resource_kinds[resource.kind]
	result = ["spec", "template", "spec", "volumes"]
}

# get_volumes_path - get resource volumes paths for "Pod"
get_volumes_path(resource) := result if {
	resource.kind == "Pod"
	result = ["spec", "volumes"]
}

# get_volumes_path - get resource volumes paths for "CronJob"
get_volumes_path(resource) := result if {
	resource.kind == "CronJob"
	result = ["spec", "jobTemplate", "spec", "template", "spec", "volumes"]
}

is_same_namespace(metadata1, metadata2) if {
	metadata1.namespace == metadata2.namespace
}

is_same_namespace(metadata1, metadata2) if {
	not metadata1.namespace
	not metadata2.namespace
}

is_same_namespace(metadata1, metadata2) if {
	not metadata2.namespace
	metadata1.namespace == "default"
}

is_same_namespace(metadata1, metadata2) if {
	not metadata1.namespace
	metadata2.namespace == "default"
}
