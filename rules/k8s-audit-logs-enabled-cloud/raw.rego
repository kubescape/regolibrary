package armo_builtins
import data.cautils as cautils

# Check if audit logs is enabled for GKE
deny[msga] {
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
		"fixCommand":"",
		"alertObject": {
			"k8sApiObjects": [],
            "externalObjects": cluster_config
		}
	}
}


# Check if audit logs is enabled for EKS
deny[msga] {
	cluster_config := input[_]
	cluster_config.apiVersion == "eks.amazonaws.com/v1"
	cluster_config.kind == "ClusterDescribe"
    cluster_config.metadata.provider == "eks"	
	config := cluster_config.data
    # logSetup is an object representing the enabled or disabled Kubernetes control plane logs for your cluster.
    # types - available cluster control plane log types
    # https://docs.aws.amazon.com/eks/latest/APIReference/API_LogSetup.html
    goodTypes := [logSetup  | logSetup =  config.Cluster.Logging.ClusterLogging[_];  isAuditLogs(logSetup)]
    count(goodTypes) == 0
	
	msga := {
		"alertMessage": "audit logs is disabled",
		"alertScore": 3,
		"packagename": "armo_builtins",
		"failedPaths": [],
		"fixCommand":"aws eks update-cluster-config --region <region_code> --name <cluster_name> --logging '{'clusterLogging':[{'types':['<api/audit/authenticator>'],'enabled':true}]}'",
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [],
			"externalObjects": cluster_config
		}
	}
}


is_logging_disabled(cluster_config) {
	not cluster_config.logging_config.component_config.enable_components
}
is_logging_disabled(cluster_config) {
	cluster_config.logging_config.component_config.enable_components
	count(cluster_config.logging_config.component_config.enable_components) == 0
}

isAuditLogs(logSetup) {
    logSetup.Enabled == true
    cautils.list_contains(logSetup.Types, "api")
}

isAuditLogs(logSetup) {
    logSetup.Enabled == true
    cautils.list_contains(logSetup.Types, "audit")
}

isAuditLogs(logSetup) {
    logSetup.enabled == true
    cautils.list_contains(logSetup.Types, "authenticator")
}