package armo_builtins

import rego.v1

# Check if PSP is enabled for GKE
deny contains msga if {
	cluster_config := input[_]
	cluster_config.apiVersion == "container.googleapis.com/v1"
	cluster_config.kind == "ClusterDescribe"
	cluster_config.metadata.provider == "gke"
	config := cluster_config.data
	not config.pod_security_policy_config.enabled == true

	msga := {
		"alertMessage": "pod security policy configuration is not enabled",
		"alertScore": 3,
		"packagename": "armo_builtins",
		"failedPaths": [],
		"fixPaths": [],
		"fixCommand": "gcloud beta container clusters update <cluster_name> --enable-pod-security-policy",
		"alertObject": {
			"k8sApiObjects": [],
			"externalObjects": cluster_config,
		},
	}
}
