package armo_builtins


# Check if EndpointPrivateAccess in enabled for EKS
deny[msga] {
	cluster_config := input[_]
	cluster_config.apiVersion == "eks.amazonaws.com/v1"
	cluster_config.kind == "ClusterDescribe"
    cluster_config.metadata.provider == "eks"	
	config = cluster_config.data

	config.Cluster.ResourcesVpcConfig.EndpointPublicAccess == true

	# check if node is private
	config.Cluster.ResourcesVpcConfig.PublicAccessCidrs[_] == "0.0.0.0/0"
	
	msga := {
		"alertMessage": "endpointPrublicAccess is enabled on a private node",
		"alertScore": 3,
		"packagename": "armo_builtins",
		"failedPaths": [],
		"fixPaths": [],
		"fixCommand": "aws eks update-cluster-config --region $AWS_REGION --name $CLUSTER_NAME --resources-vpc-config endpointPrivateAccess=true,endpointPublicAccess=false",
		"alertObject": {
			"k8sApiObjects": [],
            "externalObjects": cluster_config
		}
	}
}


