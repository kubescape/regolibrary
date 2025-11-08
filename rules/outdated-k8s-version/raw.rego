package armo_builtins

import rego.v1

deny contains msga if {
	node := input[_]
	node.kind == "Node"
	current_version := node.status.nodeInfo.kubeletVersion
	has_outdated_version(current_version)
	path := "status.nodeInfo.kubeletVersion"
	msga := {
		"alertMessage": sprintf("Your kubelet version: %s, in node: %s is outdated", [current_version, node.metadata.name]),
		"reviewPaths": [path],
		"alertObject": {"k8SApiObjects": [node]},
	}
}

has_outdated_version(version) if {
	# the `supported_k8s_versions` is validated in the validations script against "https://api.github.com/repos/kubernetes/kubernetes/releases"
	supported_k8s_versions := ["v1.34", "v1.33", "v1.32"]
	every v in supported_k8s_versions {
		not startswith(version, v)
	}
}
