package armo_builtins
import data
# Check for images from blocklisted repos

untrustedImageRepo[msga] {
	pod := input[_]
	k := pod.kind
	k == "Pod"
	container := pod.spec.containers[i]
	path := sprintf("spec.containers[%v].image", [format_int(i, 10)])
	image := container.image
    untrusted_or_public_registries(image)

	msga := {
		"alertMessage": sprintf("image '%v' in container '%s' comes from untrusted registry", [image, container.name]),
		"packagename": "armo_builtins",
		"alertScore": 2,
		"fixPaths": [],
		"failedPaths": [path],
         "alertObject": {
			"k8sApiObjects": [pod]
		}
    }
}

untrustedImageRepo[msga] {
	wl := input[_]
	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	spec_template_spec_patterns[wl.kind]
	container := wl.spec.template.spec.containers[i]
	path := sprintf("spec.template.spec.containers[%v].image", [format_int(i, 10)])
	image := container.image
    untrusted_or_public_registries(image)

	msga := {
		"alertMessage": sprintf("image '%v' in container '%s' comes from untrusted registry", [image, container.name]),
		"packagename": "armo_builtins",
		"alertScore": 2,
		"fixPaths": [],
		"failedPaths": [path],
         "alertObject": {
			"k8sApiObjects": [wl]
		}
    }
}

untrustedImageRepo[msga] {
	wl := input[_]
	wl.kind == "CronJob"
	container := wl.spec.jobTemplate.spec.template.spec.containers[i]
	path := sprintf("spec.jobTemplate.spec.template.spec.containers[%v].image", [format_int(i, 10)])
	image := container.image
    untrusted_or_public_registries(image)

	msga := {
		"alertMessage": sprintf("image '%v' in container '%s' comes from untrusted registry", [image, container.name]),
		"packagename": "armo_builtins",
		"alertScore": 2,
		"fixPaths": [],
		"failedPaths": [path],
        "alertObject": {
			"k8sApiObjects": [wl]
		}
    }
}

# see default-config-inputs.json for list values

#### Untrusted
untrusted_or_public_registries(image){
	repo_prefix := data.postureControlInputs.untrustedRegistries[_]
	startswith(image, repo_prefix)
	# check that is not on allowlist
	data.postureControlInputs.untrustedRegistriesAllowlist
	repo_allowlist_prefix_list := [repo_allowlist_prefix |  repo_allowlist_prefix= data.postureControlInputs.untrustedRegistriesAllowlist[_]; startswith(image, repo_allowlist_prefix)]
	count(repo_allowlist_prefix_list) == 0
}

untrusted_or_public_registries(image){
	repo_prefix := data.postureControlInputs.untrustedRegistries[_]
	startswith(image, repo_prefix)
	not data.postureControlInputs.untrustedRegistriesAllowlist
}



#### Public
untrusted_or_public_registries(image){
	repo_prefix := data.postureControlInputs.publicRegistries[_]
	startswith(image, repo_prefix)
	# check that is not on allowlist
	data.postureControlInputs.publicRegistriesAllowlist
	repo_allowlist_prefix_list := [repo_allowlist_prefix |  repo_allowlist_prefix= data.postureControlInputs.publicRegistriesAllowlist[_]; startswith(image, repo_allowlist_prefix)]
	count(repo_allowlist_prefix_list) == 0
}

untrusted_or_public_registries(image){
	repo_prefix := data.postureControlInputs.publicRegistries[_]
	startswith(image, repo_prefix)
	not data.postureControlInputs.publicRegistriesAllowlist
}

untrusted_or_public_registries(image){
	# the lack of registry name defaults to docker hub
	not contains(image, "/")
}