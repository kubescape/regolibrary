package armo_builtins
import data.kubernetes.api.client as client
import data

# loadbalancer
deny[msga] {
	wl := input[_]
	workload_types = {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job", "Pod", "CronJob"}
	workload_types[wl.kind]

    # "Apache NiFi", Kubeflow, "Argo Workflows", "Weave Scope", "Kubernetes dashboard".
    wl_names := data.postureControlInputs.sensitiveInterfaces
	wl_name := wl_names[_]
	contains(wl.metadata.name, wl_name)

	wlvector = {"name": wl.metadata.name,
				"namespace": wl.metadata.namespace,
				"kind": wl.kind,
				"relatedObjects": []}

	msga := {
		"alertMessage": sprintf("wl: %v is in the cluster", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [""],
		"alertObject": {
			"k8sApiObjects": [],
            "externalObjects": wlvector
		}
	}
}


# nodePort
# get a pod connected to that service, get nodeIP (hostIP?)
# use ip + nodeport
deny[msga] {
	wl := input[_]
	wl.kind == "Pod"
    
    # "Apache NiFi", Kubeflow, "Argo Workflows", "Weave Scope", "Kubernetes dashboard".
    wl_names := data.postureControlInputs.sensitiveInterfaces
	wl_name := wl_names[_]
	contains(wl.metadata.name, wl_name)

	wlvector = {"name": wl.metadata.name,
				"namespace": wl.metadata.namespace,
				"kind": wl.kind,
				"relatedObjects": []}

	msga := {
		"alertMessage": sprintf("wl: %v is in the cluster", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [""],
		"alertObject": {
			"k8sApiObjects": [],
            "externalObjects": wlvector
		}
	}
} 

# nodePort
# get a workload connected to that service, get nodeIP (hostIP?)
# use ip + nodeport
deny[msga] {
	wl := input[_]
	spec_template_spec_patterns := {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job", "CronJob"}
	spec_template_spec_patterns[wl.kind]
    
    # "Apache NiFi", Kubeflow, "Argo Workflows", "Weave Scope", "Kubernetes dashboard".
    wl_names := data.postureControlInputs.sensitiveInterfaces
	wl_name := wl_names[_]
	contains(wl.metadata.name, wl_name)

	wlvector = {"name": wl.metadata.name,
				"namespace": wl.metadata.namespace,
				"kind": wl.kind,
				"relatedObjects": []}

	msga := {
		"alertMessage": sprintf("wl: %v is in the cluster", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [""],
		"alertObject": {
			"k8sApiObjects": [],
            "externalObjects": wlvector
		}
	}
}
