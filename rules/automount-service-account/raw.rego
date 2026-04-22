package armo_builtins

# This rule honours Kubernetes precedence: pod.spec.automountServiceAccountToken
# overrides serviceAccount.automountServiceAccountToken. It alerts only on
# workloads that will actually mount a token (pod-level true, or pod-level
# unset with an SA that does not explicitly disable).


# POD
deny[msga] {
	pod := input[_]
	pod.kind == "Pod"

	start_of_path := "spec."
	wl_namespace := pod_namespace(pod)
	result := is_sa_auto_mounted(pod.spec, start_of_path, wl_namespace)
	failed_path := get_failed_path(result)
	fixed_path := get_fixed_path(result)

	msga := {
		"alertMessage": sprintf("Pod: %v in the following namespace: %v mounts service account tokens by default", [pod.metadata.name, wl_namespace]),
		"alertScore": 9,
		"packagename": "armo_builtins",
		"fixPaths": fixed_path,
		"failedPaths": failed_path,
		"alertObject": {"k8sApiObjects": [pod]},
	}
}

# WORKLOADS: Deployment / ReplicaSet / DaemonSet / StatefulSet / Job
deny[msga] {
	wl := input[_]
	spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	spec_template_spec_patterns[wl.kind]

	start_of_path := "spec.template.spec."
	wl_namespace := pod_namespace(wl)
	result := is_sa_auto_mounted(wl.spec.template.spec, start_of_path, wl_namespace)
	failed_path := get_failed_path(result)
	fixed_path := get_fixed_path(result)

	msga := {
		"alertMessage": sprintf("%v: %v in the following namespace: %v mounts service account tokens by default", [wl.kind, wl.metadata.name, wl_namespace]),
		"alertScore": 7,
		"packagename": "armo_builtins",
		"fixPaths": fixed_path,
		"failedPaths": failed_path,
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

# CRONJOB
deny[msga] {
	wl := input[_]
	wl.kind == "CronJob"

	start_of_path := "spec.jobTemplate.spec.template.spec."
	wl_namespace := pod_namespace(wl)
	result := is_sa_auto_mounted(wl.spec.jobTemplate.spec.template.spec, start_of_path, wl_namespace)
	failed_path := get_failed_path(result)
	fixed_path := get_fixed_path(result)

	msga := {
		"alertMessage": sprintf("%v: %v in the following namespace: %v mounts service account tokens by default", [wl.kind, wl.metadata.name, wl_namespace]),
		"alertScore": 7,
		"packagename": "armo_builtins",
		"fixPaths": fixed_path,
		"failedPaths": failed_path,
		"alertObject": {"k8sApiObjects": [wl]},
	}
}


# ----- decision helpers -----

# Branch 1: pod spec explicitly sets automountServiceAccountToken: true.
# Pod-level wins over SA, so this always mounts. Fix by setting the pod
# field to false - deleting it is unsafe because it falls back to the SA,
# which may also enable auto-mount.
is_sa_auto_mounted(spec, start_of_path, wl_namespace) = [failed_path, fix_path] {
	spec.automountServiceAccountToken == true

	failed_path := sprintf("%vautomountServiceAccountToken", [start_of_path])
	fix_path := {"path": sprintf("%vautomountServiceAccountToken", [start_of_path]), "value": "false"}
}

# Branch 2: pod spec does not set automountServiceAccountToken, and the
# referenced SA exists and does not explicitly disable auto-mount. Token
# will mount by default. Fix by setting pod-level to false.
is_sa_auto_mounted(spec, start_of_path, wl_namespace) = [failed_path, fix_path] {
	not spec.automountServiceAccountToken == false
	not spec.automountServiceAccountToken == true

	sa := input[_]
	sa.kind == "ServiceAccount"
	is_same_sa(spec, sa.metadata.name)
	is_same_namespace(sa.metadata.namespace, wl_namespace)
	not sa.automountServiceAccountToken == false

	fix_path := {"path": sprintf("%vautomountServiceAccountToken", [start_of_path]), "value": "false"}
	failed_path := ""
}

# Branch 3: pod spec does not set automountServiceAccountToken, and no
# matching SA is in the input (YAML scan, or SA not scanned). Kubernetes
# default is to mount, so flag it.
is_sa_auto_mounted(spec, start_of_path, wl_namespace) = [failed_path, fix_path] {
	not spec.automountServiceAccountToken == false
	not spec.automountServiceAccountToken == true

	not matching_sa_exists(spec, wl_namespace)

	fix_path := {"path": sprintf("%vautomountServiceAccountToken", [start_of_path]), "value": "false"}
	failed_path := ""
}

# No branch when spec.automountServiceAccountToken == false: pod-level
# disable wins over any SA setting, so no deny.


matching_sa_exists(spec, wl_namespace) {
	sa := input[_]
	sa.kind == "ServiceAccount"
	is_same_sa(spec, sa.metadata.name)
	is_same_namespace(sa.metadata.namespace, wl_namespace)
}


get_failed_path(paths) = [paths[0]] {
	paths[0] != ""
} else = []

get_fixed_path(paths) = [paths[1]] {
	paths[1] != ""
} else = []


# ----- matching helpers -----

pod_namespace(obj) = ns {
	ns := obj.metadata.namespace
} else = "default" {
	true
}

is_same_sa(spec, serviceAccountName) {
	spec.serviceAccountName == serviceAccountName
}

is_same_sa(spec, serviceAccountName) {
	not spec.serviceAccountName
	serviceAccountName == "default"
}

is_same_namespace(ns1, ns2) {
	ns1 == ns2
}

is_same_namespace(ns1, ns2) {
	not ns1
	ns2 == "default"
}

is_same_namespace(ns1, ns2) {
	not ns2
	ns1 == "default"
}
