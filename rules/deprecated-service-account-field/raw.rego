# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

deprecated_service_account_msg(obj, deprecated_path, replacement_path, value) := {
	"alertMessage": sprintf("%v: %v uses deprecated field '%v'; use '%v' instead", [obj.kind, obj.metadata.name, deprecated_path, replacement_path]),
	"packagename": "armo_builtins",
	"failedPaths": [deprecated_path],
	"deletePaths": [deprecated_path],
	"fixPaths": [{"path": replacement_path, "value": value}],
	"alertScore": 3,
	"alertObject": {"k8sApiObjects": [obj]},
}

deprecated_service_account_mismatch_msg(obj, deprecated_path, value, replacement_path, replacement_value) := {
	"alertMessage": sprintf("%v: %v has deprecated field '%v' (%v) and '%v' (%v) with non-matching values; remove '%v' or make the values match", [obj.kind, obj.metadata.name, deprecated_path, value, replacement_path, replacement_value, deprecated_path]),
	"packagename": "armo_builtins",
	"failedPaths": [deprecated_path],
	"deletePaths": [deprecated_path],
	"fixPaths": [],
	"alertScore": 3,
	"alertObject": {"k8sApiObjects": [obj]},
}

is_workload_kind(kind) if {
	{"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job", "ReplicationController"}[kind]
}

deny contains msga if {
	pod := input[_]
	pod.kind == "Pod"
	value := pod.spec.serviceAccount
	replacement_value := object.get(pod.spec, "serviceAccountName", "")
	value != replacement_value
	replacement_value == ""

	msga := deprecated_service_account_msg(pod, "spec.serviceAccount", "spec.serviceAccountName", value)
}

deny contains msga if {
	pod := input[_]
	pod.kind == "Pod"
	value := pod.spec.serviceAccount
	replacement_value := pod.spec.serviceAccountName
	value != replacement_value

	msga := deprecated_service_account_mismatch_msg(pod, "spec.serviceAccount", value, "spec.serviceAccountName", replacement_value)
}

deny contains msga if {
	wl := input[_]
	is_workload_kind(wl.kind)
	value := wl.spec.template.spec.serviceAccount
	replacement_value := object.get(wl.spec.template.spec, "serviceAccountName", "")
	value != replacement_value
	replacement_value == ""

	msga := deprecated_service_account_msg(wl, "spec.template.spec.serviceAccount", "spec.template.spec.serviceAccountName", value)
}

deny contains msga if {
	wl := input[_]
	is_workload_kind(wl.kind)
	value := wl.spec.template.spec.serviceAccount
	replacement_value := wl.spec.template.spec.serviceAccountName
	value != replacement_value

	msga := deprecated_service_account_mismatch_msg(wl, "spec.template.spec.serviceAccount", value, "spec.template.spec.serviceAccountName", replacement_value)
}

deny contains msga if {
	cronjob := input[_]
	cronjob.kind == "CronJob"
	value := cronjob.spec.jobTemplate.spec.template.spec.serviceAccount
	replacement_value := object.get(cronjob.spec.jobTemplate.spec.template.spec, "serviceAccountName", "")
	value != replacement_value
	replacement_value == ""

	msga := deprecated_service_account_msg(cronjob, "spec.jobTemplate.spec.template.spec.serviceAccount", "spec.jobTemplate.spec.template.spec.serviceAccountName", value)
}

deny contains msga if {
	cronjob := input[_]
	cronjob.kind == "CronJob"
	value := cronjob.spec.jobTemplate.spec.template.spec.serviceAccount
	replacement_value := cronjob.spec.jobTemplate.spec.template.spec.serviceAccountName
	value != replacement_value

	msga := deprecated_service_account_mismatch_msg(cronjob, "spec.jobTemplate.spec.template.spec.serviceAccount", value, "spec.jobTemplate.spec.template.spec.serviceAccountName", replacement_value)
}
