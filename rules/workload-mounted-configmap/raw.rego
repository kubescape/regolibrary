package armo_builtins

import rego.v1

deny contains msga if {
	resource := input[_]
	volumes_path := get_volumes_path(resource)
	volumes := object.get(resource, volumes_path, [])
	volume := volumes[i]
	volume.configMap

	configMap := input[_]
	configMap.kind == "ConfigMap"
	configMap.metadata.name == volume.configMap.name
	is_same_namespace(configMap.metadata, resource.metadata)

	containers_path := get_containers_path(resource)
	containers := object.get(resource, containers_path, [])
	container := containers[j]
	container.volumeMounts

	# check if volume is mounted
	container.volumeMounts[k].name == volume.name

	failedPaths := sprintf("%s[%d].volumeMounts[%d]", [concat(".", containers_path), j, k])

	msga := {
		"alertMessage": sprintf("%v: %v has mounted configMap", [resource.kind, resource.metadata.name]),
		"packagename": "armo_builtins",
		"deletePaths": [failedPaths],
		"failedPaths": [failedPaths],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [resource]},
		"relatedObjects": [{"object": configMap}],
	}
}

# get_containers_path - get resource containers paths for  {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
get_containers_path(resource) := result if {
	resource_kinds := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	resource_kinds[resource.kind]
	result = ["spec", "template", "spec", "containers"]
}

# get_containers_path - get resource containers paths for "Pod"
get_containers_path(resource) := result if {
	resource.kind == "Pod"
	result = ["spec", "containers"]
}

# get_containers_path - get resource containers paths for  "CronJob"
get_containers_path(resource) := result if {
	resource.kind == "CronJob"
	result = ["spec", "jobTemplate", "spec", "template", "spec", "containers"]
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
