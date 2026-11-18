# regal ignore:directory-package-mismatch 
package armo_builtins

import rego.v1

untrustedImageRepo contains msga if {
	wl := input[_]
	containers_path := get_containers_path(wl)[_]
	containers := object.get(wl, containers_path, [])
	container := containers[i]
	untrusted_or_public_registries(image.parse_normalized_name(lower_host(container.image)))
	name := image.parse_normalized_name(container.image)
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

untrusted_or_public_registries(image) if {
	# see default-config-inputs.json for list values
	untrusted_registries := data.postureControlInputs.untrustedRegistries
	registry := untrusted_registries[_]
	registry_match(lower(image), lower(registry))
}

untrusted_or_public_registries(image) if {
	# see default-config-inputs.json for list values
	public_registries := data.postureControlInputs.publicRegistries
	registry := public_registries[_]
	registry_match(lower(image), lower(registry))
}

# lower_host - the Docker Hub alias is only normalized when lowercase
# ('INDEX.DOCKER.IO' stays as is), so lower the host before parsing.
lower_host(img) := concat("/", array.concat([lower(parts[0])], array.slice(parts, 1, count(parts)))) if {
	parts := split(img, "/")
	count(parts) > 1
	regex.match(`[.:]`, parts[0])
} else := img

registry_match(image, registry) if {
	startswith(image, registry)
	boundary_ok(registry, trim_prefix(image, registry))
}

# Same boundary as C-0078: a host-only entry such as 'quay.io' must not match
# 'quay.io.evil.io/...' or 'quay.io:5000/...'.
boundary_ok(registry, _) if endswith(registry, "/")

boundary_ok(_, "")

boundary_ok(_, suffix) if startswith(suffix, "/")

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
