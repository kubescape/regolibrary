# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

deny contains msga if {
	policy := input[_]
	policy.kind == "NetworkPolicy"
	selector := object.get(policy.spec, "podSelector", {})
	count(selector) > 0
	namespace := object.get(policy.metadata, "namespace", "default")

	not has_matching_workload(policy, namespace, input)

	msga := {
		"alertMessage": sprintf("NetworkPolicy '%v' podSelector matches no workloads in namespace '%v'", [policy.metadata.name, namespace]),
		"packagename": "armo_builtins",
		"failedPaths": ["spec.podSelector"],
		"fixPaths": [],
		"alertScore": 4,
		"alertObject": {"k8sApiObjects": [policy]},
	}
}

has_matching_workload(policy, namespace, resources) if {
	wl := resources[_]
	is_workload(wl)
	object.get(wl.metadata, "namespace", "default") == namespace
	match_labels := object.get(policy.spec.podSelector, "matchLabels", {})
	labels_match(match_labels, pod_template_labels(wl))
}

is_workload(wl) if {
	workload_kinds := {"Pod", "Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job", "CronJob", "ReplicationController"}
	workload_kinds[wl.kind]
}

pod_template_labels(wl) := labels if {
	wl.kind == "Pod"
	labels := object.get(wl.metadata, "labels", {})
}

pod_template_labels(wl) := labels if {
	controller_kinds := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job", "ReplicationController"}
	controller_kinds[wl.kind]
	labels := object.get(wl.spec.template.metadata, "labels", {})
}

pod_template_labels(wl) := labels if {
	wl.kind == "CronJob"
	labels := object.get(wl.spec.jobTemplate.spec.template.metadata, "labels", {})
}

labels_match(selector, labels) if {
	count(selector) > 0
	not selector_mismatch(selector, labels)
}

selector_mismatch(selector, labels) if {
	selector[k]
	not labels[k] == selector[k]
}
