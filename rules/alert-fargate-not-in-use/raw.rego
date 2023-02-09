package armo_builtins




# deny if fargate is not being used in any of the nodes in cluster.
# a Node is identified as using fargate if it's name starts with 'fargate'.
deny[msga] {


    # get all nodes
    nodes := [node | node = input[_]; node.kind == "Node"]
    count(nodes) > 0

    # get all nodes without fargate
    nodes_not_fargate := [node | node = nodes[_]; not startswith(node.metadata.name, "fargate")]

    # if count of all nodes equals to count of nodes_not_fargate it means fargate is not being used.
    count(nodes) == count(nodes_not_fargate)

	# prepare message data.
	alert_message :=  "Consider Fargate for running untrusted workloads"

	msga := {
		"alertMessage": alert_message,
		"packagename": "armo_builtins",

		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": nodes_not_fargate
		}
	}
}