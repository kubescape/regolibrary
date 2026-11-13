# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

untrustedImageRepo contains msga if {
	wl := input[_]
	containers_path := get_containers_path(wl)[_]
	containers := object.get(wl, containers_path, [])
	container := containers[i]
	name := image.parse_normalized_name(container.image)
	not image_in_allowed_list(name)
	path := sprintf("%s[%d].image", [concat(".", containers_path), i])

	msga := {
		"alertMessage": sprintf("image '%v' in container '%s' comes from untrusted registry", [name, container.name]),
		"packagename": "armo_builtins",
		"alertScore": 2,
		"fixPaths": [],
		"reviewPaths": [path],
		"failedPaths": [path],
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

# image_in_allowed_list - rule to check if an image complies with imageRepositoryAllowList.
image_in_allowed_list(image) if {
	# see default-config-inputs.json for list values
	allowedlist := data.postureControlInputs.imageRepositoryAllowList
	registry := allowedlist[_]
	startswith(image, registry)
	boundary_ok(registry, trim_prefix(image, registry))
}

# boundary_ok - the allowed entry must end at a registry/repo/tag/digest boundary:
# either the entry ends with '/', or the rest of the image is empty, starts with
# '/' or '@', or is a ':' tag. Otherwise 'registry.corp.com' would also allow an
# image from a look-alike host such as 'registry.corp.com.evil.io'.
boundary_ok(registry, _) if endswith(registry, "/")

boundary_ok(_, "")

boundary_ok(_, suffix) if startswith(suffix, "/")

# A tag can't contain '/', so a ':' followed by a '/' is a port after the host
# entry ('registry.corp.com:5000/app'): another registry endpoint, not a tag.
boundary_ok(_, suffix) if {
	startswith(suffix, ":")
	not contains(suffix, "/")
}

boundary_ok(_, suffix) if startswith(suffix, "@")

# get_containers_path - get resource containers paths for  {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
get_containers_path(resource) := result if {
	resource_kinds := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	resource_kinds[resource.kind]
	result = {
		["spec", "template", "spec", "containers"],
		["spec", "template", "spec", "initContainers"],
	}
}

# get_containers_path - get resource containers paths for "Pod"
get_containers_path(resource) := result if {
	resource.kind == "Pod"
	result = {
		["spec", "containers"],
		["spec", "initContainers"],
		["spec", "ephemeralContainers"],
	}
}

# get_containers_path - get resource containers paths for  "CronJob"
get_containers_path(resource) := result if {
	resource.kind == "CronJob"
	result = {
		["spec", "jobTemplate", "spec", "template", "spec", "containers"],
		["spec", "jobTemplate", "spec", "template", "spec", "initContainers"],
	}
}
