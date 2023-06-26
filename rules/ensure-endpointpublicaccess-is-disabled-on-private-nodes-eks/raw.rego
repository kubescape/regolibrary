package armo_builtins

import future.keywords.in

# Check if EndpointPublicAccess in enabled on a private node for EKS. A private node is a node with no public ips access.
deny[msga] {
	cluster_config := input[_]
	cluster_config.apiVersion == "eks.amazonaws.com/v1"
	cluster_config.kind == "ClusterDescribe"
    cluster_config.metadata.provider == "eks"
	config := cluster_config.data

	config.Cluster.ResourcesVpcConfig.EndpointPublicAccess == true

	# filter out private nodes
	"0.0.0.0/0" in config.Cluster.ResourcesVpcConfig.PublicAccessCidrs

	msga := {
		"alertMessage": "endpointPublicAccess is enabled on a private node",
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


