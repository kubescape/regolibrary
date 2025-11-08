package armo_builtins

import rego.v1

# Check if EndpointPrivateAccess in disabled or EndpointPublicAccess is enabled for EKS
deny contains msga if {
	cluster_config := input[_]
	cluster_config.apiVersion == "eks.amazonaws.com/v1"
	cluster_config.kind == "ClusterDescribe"
	cluster_config.metadata.provider == "eks"
	config = cluster_config.data

	is_endpointaccess_misconfigured(config)

	msga := {
		"alertMessage": "endpointPrivateAccess is not enabled, or EndpointPublicAccess is enabled",
		"alertScore": 3,
		"packagename": "armo_builtins",
		"failedPaths": [],
		"fixPaths": [],
		"fixCommand": "aws eks update-cluster-config --region $AWS_REGION --name $CLUSTER_NAME --resources-vpc-config endpointPrivateAccess=true,endpointPublicAccess=true,publicAccessCidrs='203.0.113.5/32'",
		"alertObject": {
			"k8sApiObjects": [],
			"externalObjects": cluster_config,
		},
	}
}

# check if EndpointPrivateAccess is disabled
is_endpointaccess_misconfigured(config) if {
	config.Cluster.ResourcesVpcConfig.EndpointPrivateAccess == false
}

# check if EndpointPublicAccess is enabled
is_endpointaccess_misconfigured(config) if {
	config.Cluster.ResourcesVpcConfig.EndpointPublicAccess == true
}
