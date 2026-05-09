package armo_builtins

deprecated_service_account_msg(obj, deprecated_path, replacement_path, value) = {
	"alertMessage": sprintf("%v: %v uses deprecated field '%v'; use '%v' instead", [obj.kind, obj.metadata.name, deprecated_path, replacement_path]),
	"packagename": "armo_builtins",
	"failedPaths": [deprecated_path],
	"deletePaths": [deprecated_path],
	"fixPaths": [{"path": replacement_path, "value": value}],
	"alertScore": 3,
	"alertObject": {
		"k8sApiObjects": [obj],
	},
}

deny[msga] {
	pod := input[_]
	pod.kind == "Pod"
	value := pod.spec.serviceAccount

	msga := deprecated_service_account_msg(pod, "spec.serviceAccount", "spec.serviceAccountName", value)
}

deny[msga] {
	wl := input[_]
	workload_kinds := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job", "ReplicationController"}
	workload_kinds[wl.kind]
	value := wl.spec.template.spec.serviceAccount

	msga := deprecated_service_account_msg(wl, "spec.template.spec.serviceAccount", "spec.template.spec.serviceAccountName", value)
}

deny[msga] {
	cronjob := input[_]
	cronjob.kind == "CronJob"
	value := cronjob.spec.jobTemplate.spec.template.spec.serviceAccount

	msga := deprecated_service_account_msg(cronjob, "spec.jobTemplate.spec.template.spec.serviceAccount", "spec.jobTemplate.spec.template.spec.serviceAccountName", value)
}
