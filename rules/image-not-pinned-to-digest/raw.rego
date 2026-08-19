# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

# has_digest - true when the image reference ends with a valid pinned digest.
# Registered OCI algorithms use their exact lowercase hexadecimal lengths;
# unregistered algorithms use the generic digest grammar.
has_digest(image) if {
	regex.match(`@sha256:[a-f0-9]{64}$`, image)
}

has_digest(image) if {
	regex.match(`@sha512:[a-f0-9]{128}$`, image)
}

has_digest(image) if {
	regex.match(`@blake3:[a-f0-9]{64}$`, image)
}

# Keep generic validation for unregistered digest algorithms.
has_digest(image) if {
	regex.match(`@([a-z0-9]+([.+_-][a-z0-9]+)*):[a-zA-Z0-9=_-]{32,}$`, image)
	not regex.match(`@(sha256|sha512|blake3):`, image)
}

# exempted_repository - true when the image belongs to a user-configured exempt repository
# (see default-config-inputs.json for the imageDigestExemptRepositories list).
# The match is enforced at a repository boundary so a near-miss prefix
# (e.g. 'internal-registry-attacker') cannot bypass an exemption for 'internal-registry'.
exempted_repository(image) if {
	exempt_repos := data.postureControlInputs.imageDigestExemptRepositories
	repository := exempt_repos[_]
	startswith(image, repository)
	boundary_ok(trim_prefix(image, repository))
}

# boundary_ok - the remainder after the exempt prefix must start at a repo/tag/digest
# separator ('/', ':', '@') or be empty; anything else means a differently-named repo.
boundary_ok("")

boundary_ok(suffix) if startswith(suffix, "/")

boundary_ok(suffix) if startswith(suffix, ":")

boundary_ok(suffix) if startswith(suffix, "@")

# base_paths - container spec path for the given resource kind.
base_paths(resource) := ["spec"] if {
	resource.kind == "Pod"
}

base_paths(resource) := ["spec", "template", "spec"] if {
	resource.kind in {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
}

base_paths(resource) := ["spec", "jobTemplate", "spec", "template", "spec"] if {
	resource.kind == "CronJob"
}

# Fails if any container, initContainer or ephemeralContainer image is not pinned to a digest
deny contains msga if {
	wl := input[_]
	wl.kind in {"Pod", "Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job", "CronJob"}

	ctype := {"containers", "initContainers", "ephemeralContainers"}[_]
	containers_path := array.concat(base_paths(wl), [ctype])
	containers := object.get(wl, containers_path, [])
	container := containers[i]

	not has_digest(container.image)
	not exempted_repository(container.image)

	path := sprintf("%s[%d].image", [concat(".", containers_path), i])

	msga := {
		"alertMessage": sprintf("%s %s: container '%s' image '%s' is not pinned to a digest", [wl.kind, wl.metadata.name, container.name, container.image]),
		"packagename": "armo_builtins",
		"alertScore": 3,
		"fixPaths": [],
		"reviewPaths": [path],
		"failedPaths": [path],
		"alertObject": {"k8sApiObjects": [wl]},
	}
}
