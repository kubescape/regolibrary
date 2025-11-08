package armo_builtins

import rego.v1

deny contains msga if {
	provider := data.dataControlInputs.cloudProvider
	provider != ""
	resources := input[_]
	spec_data := get_pod_spec(resources)
	spec := spec_data.spec
	volumes := spec.volumes
	volume := volumes[i]
	start_of_path := spec_data.start_of_path
	result := is_unsafe_paths(volume, start_of_path, provider, i)
	volumeMounts := spec.containers[j].volumeMounts
	pathMounts = volume_mounts(volume.name, volumeMounts, sprintf("%vcontainers[%d]", [start_of_path, j]))
	finalPath := array.concat([result], pathMounts)

	msga := {
		"alertMessage": sprintf("%v: %v has: %v as volume with potential credentials access.", [resources.kind, resources.metadata.name, volume.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"deletePaths": finalPath,
		"failedPaths": finalPath,
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [resources]},
	}
}

# get_volume - get resource spec paths for {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
get_pod_spec(resources) := result if {
	resources_kinds := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	resources_kinds[resources.kind]
	result = {"spec": resources.spec.template.spec, "start_of_path": "spec.template.spec."}
}

# get_volume - get resource spec paths for "Pod"
get_pod_spec(resources) := result if {
	resources.kind == "Pod"
	result = {"spec": resources.spec, "start_of_path": "spec."}
}

# get_volume - get resource spec paths for "CronJob"
get_pod_spec(resources) := result if {
	resources.kind == "CronJob"
	result = {"spec": resources.spec.jobTemplate.spec.template.spec, "start_of_path": "spec.jobTemplate.spec.template.spec."}
}

# is_unsafe_paths - looking for cloud provider (eks/gke/aks) paths that have the potential of accessing credentials
is_unsafe_paths(volume, start_of_path, provider, i) := result if {
	unsafe := unsafe_paths(provider)
	unsafe[_] == fix_path(volume.hostPath.path)
	result = sprintf("%vvolumes[%d]", [start_of_path, i])
}

# fix_path - adding "/" at the end of the path if doesn't exist and if not a file path.
fix_path(path) := result if {
	# filter file path
	not regex.match(`[\\w-]+\\.`, path)

	# filter path that doesn't end with "/"
	not endswith(path, "/")

	# adding "/" to the end of the path
	result = sprintf("%v/", [path])
} else := path

# eks unsafe paths
unsafe_paths(x) := [
	"/.aws/",
	"/.aws/config/",
	"/.aws/credentials/",
] if {
	x == "eks"
}

# aks unsafe paths
unsafe_paths(x) := [
	"/etc/",
	"/etc/kubernetes/",
	"/etc/kubernetes/azure.json",
	"/.azure/",
	"/.azure/credentials/",
	"/etc/kubernetes/azure.json",
] if {
	x == "aks"
}

# gke unsafe paths
unsafe_paths(x) := [
	"/.config/gcloud/",
	"/.config/",
	"/gcloud/",
	"/.config/gcloud/application_default_credentials.json",
	"/gcloud/application_default_credentials.json",
] if {
	x == "gke"
}

volume_mounts(name, volume_mounts, str) := [path] if {
	name == volume_mounts[j].name
	path := sprintf("%s.volumeMounts[%v]", [str, j])
} else := []
