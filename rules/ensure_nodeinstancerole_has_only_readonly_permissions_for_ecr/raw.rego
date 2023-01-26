package armo_builtins

import future.keywords.if
import future.keywords.every

# deny if a NodeInstanceRole has a poloicy that is not AmazonEC2ContainerRegistryReadOnly
deny[msg] {
	resources := input[_]
	resources.kind == "ListEntitiesForPolicies"
	resources.metadata.provider == "eks"
    
    # filter out policies that are not AmazonEC2ContainerRegistryReadOnly
    ec2_readonly_policies_names := [key | resources.data.rolesPolicies[key]; not endswith(key, "AmazonEC2ContainerRegistryReadOnly")]
    
	# construct a new object with the filtered policies
	ec2_readonly_policies := object.filter(resources.data.rolesPolicies, ec2_readonly_policies_names)
    
	# check if the filtered policies are attached to a NodeInstanceRole
    is_NodeInstanceRole(ec2_readonly_policies)


	msg := {
		"alertMessage": "Cluster has none read-only access to ECR; Review AWS ECS worker node IAM role (NodeInstanceRole) IAM Policy Permissions to verify that they are set and the minimum required level.",
		"packagename": "armo_builtins",

		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {
			"externalObjects": resources
		}
	}
}


# is_NodeInstanceRole - return true if the policy is attached to a NodeInstanceRole
is_NodeInstanceRole(policies) {
    some key, _ in policies
    contains(policies[key].PolicyRoles[_].RoleName,"NodeInstanceRole")
}