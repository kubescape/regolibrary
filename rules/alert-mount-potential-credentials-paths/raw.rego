package armo_builtins
import future.keywords.if


deny[msga] {
	provider := data.dataControlInputs.cloudProvider
	provider != ""
	resources := input[_]
	volumes_data := get_volumes(resources)
    volumes := volumes_data["volumes"]
    volume := volumes[i]
	beginning_of_path := volumes_data["beginning_of_path"]
    result := is_unsafe_paths(volume, beginning_of_path, provider,i)

	msga := {
		"alertMessage": sprintf("%v: %v has: %v as volume with potential credentials access.", [resources.kind, resources.metadata.name, volume.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [result],
		"fixPaths":[],
		"alertObject": {
			"k8sApiObjects": [resources]
		}
	}	
}

	
# get_volume - get resource volumes paths for {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
get_volumes(resources) := result {
	resources_kinds := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	resources_kinds[resources.kind]
	result = {"volumes": resources.spec.template.spec.volumes, "beginning_of_path": "spec.template.spec."}
}

# get_volume - get resource volumes paths for "Pod"
get_volumes(resources) := result {
	resources.kind == "Pod"
	result = {"volumes": resources.spec.volumes, "beginning_of_path": "spec."}
}

# get_volume - get resource volumes paths for "CronJob"
get_volumes(resources) := result {
	resources.kind == "CronJob"
	result = {"volumes": resources.spec.jobTemplate.spec.template.spec.volumes, "beginning_of_path": "spec.jobTemplate.spec.template.spec."}
}


# is_unsafe_paths - looking for cloud provider (eks/gke/aks) paths that have the potential of accessing credentials
is_unsafe_paths(volume, beginning_of_path, provider, i) = result {
	unsafe :=  unsafe_paths(provider)
	unsafe[_] == fix_path(volume.hostPath.path)
	result= sprintf("%vvolumes[%d].hostPath.path", [beginning_of_path, i])
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
unsafe_paths(x) := ["/.aws/", 
					"/.aws/config/", 
					"/.aws/credentials/"] if {x=="eks"}

# aks unsafe paths
unsafe_paths(x) := ["/etc/",
					"/etc/kubernetes/",
					"/etc/kubernetes/azure.json", 
					"/.azure/",
					"/.azure/credentials/", 
					"/etc/kubernetes/azure.json"] if {x=="aks"}

# gke unsafe paths
unsafe_paths(x) := ["/.config/gcloud/", 
					"/.config/", 
					"/gcloud/", 
					"/.config/gcloud/application_default_credentials.json",
					"/gcloud/application_default_credentials.json"] if {x=="gke"}

