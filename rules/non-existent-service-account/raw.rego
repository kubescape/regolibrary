# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

deny contains msga if {
	wl := input[_]
	info := workload_info(wl)
	sa := service_account_field(info.spec)
	wl_namespace := namespace(wl)

	not service_account_exists(sa.name, wl_namespace)

	msga := {
		"alertMessage": sprintf("%v: %v in namespace %v references missing ServiceAccount %v", [wl.kind, wl.metadata.name, wl_namespace, sa.name]),
		"packagename": "armo_builtins",
		"failedPaths": [sprintf("%v%v", [info.path, sa.field])],
		"fixPaths": [],
		"alertScore": 5,
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

workload_info(wl) := {"spec": wl.spec, "path": "spec."} if {
	wl.kind == "Pod"
}

workload_info(wl) := {"spec": wl.spec.template.spec, "path": "spec.template.spec."} if {
	workload_kinds := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job", "ReplicationController"}
	workload_kinds[wl.kind]
}

workload_info(wl) := {"spec": wl.spec.jobTemplate.spec.template.spec, "path": "spec.jobTemplate.spec.template.spec."} if {
	wl.kind == "CronJob"
}

# serviceAccount is the deprecated alias of serviceAccountName, which wins when
# both are set (the API server fills serviceAccountName in, but manifests in
# file scans can carry only the alias)
service_account_field(spec) := {"name": spec.serviceAccountName, "field": "serviceAccountName"} if {
	spec.serviceAccountName != ""
} else := {"name": spec.serviceAccount, "field": "serviceAccount"} if {
	spec.serviceAccount != ""
}

service_account_exists("default", _) := true
service_account_exists("", _) := true

service_account_exists(name, wl_namespace) if {
	sa := input[_]
	sa.kind == "ServiceAccount"
	sa.metadata.name == name
	namespace(sa) == wl_namespace
}

namespace(obj) := ns if {
	ns := obj.metadata.namespace
} else := "default"
