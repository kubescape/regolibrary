package armo_builtins
# import data.cautils as cautils
# import data.kubernetes.api.client as client

# input: pods
# apiversion: v1
# fails if object has similar name to known workload (but is not from that workload)

deny[msga] {
	object := input[_]
	wanted_kinds := {"Pod", "ReplicaSet", "Job"}
	wanted_kinds[object.kind]

    wl_known_names := {"coredns", "kube-proxy", 
						"event-exporter-gke", "kube-dns", "17-default-backend", "metrics-server",
						"ca-audit", "ca-dashboard-aggregator","ca-notification-server", "ca-ocimage","ca-oracle", 
						"ca-posture", "ca-rbac", "ca-vuln-scan", "ca-webhook", "ca-websocket", "clair-clair"}
    wl_name := wl_known_names[_]
    contains(object.metadata.name, wl_name)
	
	msga := {
		"alertMessage": sprintf("this %v has a similar name to %v", [object.kind, wl_name]),
		"alertScore": 9,
		"packagename": "armo_builtins",
         "alertObject": {
			"k8sApiObjects": [object]
		}
     }
}