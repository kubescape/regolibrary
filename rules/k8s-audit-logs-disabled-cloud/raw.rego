package armo_builtins


# Check if audit logs is enabled for GKE
deny[msga] {
	clusterConfig := input[_]
	clusterConfig.kind == "ClusterDescription"
    clusterConfig.group == "cloudvendordata.armo.cloud"
    clusterConfig.provider == "gke"
    # If enableComponents is empty, it will disable logging
    # https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1beta1/projects.locations.clusters#loggingcomponentconfig
    count(clusterConfig.loggingConfig.componentConfig.enableComponents) > 0
	
	msga := {
		"alertMessage": sprintf("audit logs is disabled"),
		"alertScore": 9,
		"packagename": "armo_builtins",
		"failedPaths": ,
		"alertObject": {
			"k8sApiObjects": [],
            "externalObjects": clusterConfig
		}
	}
}


# Check if audit logs is enabled for EKS
deny[msga] {
	clusterConfig := input[_]
	clusterConfig.kind == "ClusterDescription"
    clusterConfig.group == "cloudvendordata.armo.cloud"
    clusterConfig.provider == "eks"
    # logSetup is an object representing the enabled or disabled Kubernetes control plane logs for your cluster.
    # types - available cluster control plane log types
    # https://docs.aws.amazon.com/eks/latest/APIReference/API_LogSetup.html
    goodTypes := [logSetup  | logSetup =  clusterConfig.cluster.logging.clusterLogging[_]; isAuditLogs(logSetup)]
    count(goodTypes) < 0
	
	msga := {
		"alertMessage": sprintf("audit logs is disabled"),
		"alertScore": 9,
		"packagename": "armo_builtins",
		"failedPaths": [],
		"alertObject": {
			"k8sApiObjects": [],
			"externalObjects": clusterConfig
		}
	}
}

isAuditLogs(logSetup) {
    logSetup.enabled == "true"
    cautils.list_contains(logSetup.types, "api")
}

isAuditLogs(logSetup) {
    logSetup.enabled == "true"
    cautils.list_contains(logSetup.types, "audit")
}

isAuditLogs(logSetup) {
    logSetup.enabled == "true"
    cautils.list_contains(logSetup.types, "authenticator")
}