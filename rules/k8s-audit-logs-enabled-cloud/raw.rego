package armo_builtins

import rego.v1

# =============================== GKE ===============================
# Check if audit logs is enabled for GKE
deny contains msga if {
	cluster_config := input[_]
	cluster_config.apiVersion == "container.googleapis.com/v1"
	cluster_config.kind == "ClusterDescribe"
	cluster_config.metadata.provider == "gke"
	config := cluster_config.data

	# If enableComponents is empty, it will disable logging
	# https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1beta1/projects.locations.clusters#loggingcomponentconfig
	is_logging_disabled(config)
	msga := {
		"alertMessage": "audit logs is disabled",
		"alertScore": 3,
		"packagename": "armo_builtins",
		"failedPaths": [],
		"fixPaths": [],
		"fixCommand": "",
		"alertObject": {
			"k8sApiObjects": [],
			"externalObjects": cluster_config,
		},
	}
}

is_logging_disabled(cluster_config) if {
	not cluster_config.logging_config.component_config.enable_components
}

is_logging_disabled(cluster_config) if {
	cluster_config.logging_config.component_config.enable_components
	count(cluster_config.logging_config.component_config.enable_components) == 0
}

# =============================== EKS ===============================
# Check if audit logs is enabled for EKS
deny contains msga if {
	cluster_config := input[_]
	cluster_config.apiVersion == "eks.amazonaws.com/v1"
	cluster_config.kind == "ClusterDescribe"
	cluster_config.metadata.provider == "eks"
	config := cluster_config.data

	# logSetup is an object representing the enabled or disabled Kubernetes control plane logs for your cluster.
	# types - available cluster control plane log types
	# https://docs.aws.amazon.com/eks/latest/APIReference/API_LogSetup.html
	logging_types := {"api", "audit", "authenticator", "controllerManager", "scheduler"}
	logSetups = config.Cluster.Logging.ClusterLogging
	not all_auditlogs_enabled(logSetups, logging_types)

	msga := {
		"alertMessage": "audit logs is disabled",
		"alertScore": 3,
		"packagename": "armo_builtins",
		"failedPaths": [],
		"fixCommand": "aws eks update-cluster-config --region '${REGION_CODE}' --name '${CLUSTER_NAME}' --logging '{'clusterLogging':[{'types':['api','audit','authenticator','controllerManager','scheduler'],'enabled':true}]}'",
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [],
			"externalObjects": cluster_config,
		},
	}
}

all_auditlogs_enabled(logSetups, types) if {
	every type in types {
		auditlogs_enabled(logSetups, type)
	}
}

auditlogs_enabled(logSetups, type) if {
	logSetup := logSetups[_]
	logSetup.Enabled == true
	type in logSetup.Types
}
