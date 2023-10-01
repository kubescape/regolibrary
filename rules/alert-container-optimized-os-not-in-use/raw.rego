package armo_builtins
import future.keywords.in


# checks if a node is not using a "Container-Optimized OS". 
# "Container-Optimized OS" prefixes are configured in 'container_optimized_os_prefixes'.  
# deny if 'nodes.status.nodeInfo.osImage' not starting with at least one item in 'container_optimized_os_prefixes'.
deny[msga] {

	nodes := input[_]
	nodes.kind == "Node"

	# list of "Container-Optimized OS" images prefixes 
	container_optimized_os_prefixes = ["Bottlerocket"]

	# check if osImage starts with at least one prefix
	some str in container_optimized_os_prefixes
	not startswith(nodes.status.nodeInfo.osImage, str)

	# prepare message data.
	alert_message :=  "Prefer using Container-Optimized OS when possible"

	failedPaths:= ["status.nodeInfo.osImage"]

	msga := {
		"alertMessage": alert_message,
		"packagename": "armo_builtins",

		"alertScore": 7,
		"reviewPaths": failedPaths,
		"failedPaths": failedPaths,
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [nodes]
		}
	}
}