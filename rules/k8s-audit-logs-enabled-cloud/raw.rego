package armo_builtins
import data.cautils as cautils

# Check if audit logs is enabled for GKE
deny[msga] {
	clusterConfig := input[_]
	clusterConfig.apiVersion == "container.googleapis.com/v1"
	clusterConfig.kind == "ClusterDescribe"
    clusterConfig.metadata.provider == "gke"	
	config := clusterConfig.data
	
    # If enableComponents is empty, it will disable logging
    # https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1beta1/projects.locations.clusters#loggingcomponentconfig
	isLoggingDisabled(config)
	msga := {
		"alertMessage": "audit logs is disabled",
		"alertScore": 3,
		"packagename": "armo_builtins",
		"failedPaths": [],
		"alertObject": {
			"k8sApiObjects": [],
            "externalObjects": clusterConfig
		}
	}
}


# Check if audit logs is enabled for EKS
deny[msga] {
	clusterConfig := input[_]
	clusterConfig.apiVersion == "eks.amazonaws.com/v1"
	clusterConfig.kind == "ClusterDescribe"
    clusterConfig.metadata.provider == "eks"	
	config := clusterConfig.data
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
		"alertObject": {
			"k8sApiObjects": [],
			"externalObjects": clusterConfig
		}
	}
}


isLoggingDisabled(clusterConfig) {
	not clusterConfig.logging_config.component_config.enable_components
}
isLoggingDisabled(clusterConfig) {
	clusterConfig.logging_config.component_config.enable_components
	count(clusterConfig.logging_config.component_config.enable_components) == 0
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