package armo_builtins

import future.keywords.contains
import future.keywords.if
import future.keywords.in

deny contains msga if {
	wl := input[_]
	info := workload_info(wl)
	sa_name := info.spec.serviceAccountName
	wl_namespace := namespace(wl)

	not service_account_exists(sa_name, wl_namespace)

	msga := {
		"alertMessage": sprintf("%v: %v in namespace %v references missing ServiceAccount %v", [wl.kind, wl.metadata.name, wl_namespace, sa_name]),
		"packagename": "armo_builtins",
		"failedPaths": [info.path],
		"fixPaths": [],
		"alertScore": 5,
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

workload_info(wl) := {"spec": wl.spec, "path": "spec.serviceAccountName"} if {
	wl.kind == "Pod"
}

workload_info(wl) := {"spec": wl.spec.template.spec, "path": "spec.template.spec.serviceAccountName"} if {
	workload_kinds := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}
	workload_kinds[wl.kind]
}

workload_info(wl) := {"spec": wl.spec.jobTemplate.spec.template.spec, "path": "spec.jobTemplate.spec.template.spec.serviceAccountName"} if {
	wl.kind == "CronJob"
}

service_account_exists(name, wl_namespace) if {
	sa := input[_]
	sa.kind == "ServiceAccount"
	sa.metadata.name == name
	namespace(sa) == wl_namespace
}

namespace(obj) := object.get(object.get(obj, "metadata", {}), "namespace", "default")
