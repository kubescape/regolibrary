package armo_builtins

import future.keywords.every

deny[msga] {
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


has_outdated_version(version)  {
	# the `supported_k8s_versions` is validated in the validations script against "https://api.github.com/repos/kubernetes/kubernetes/releases"
    supported_k8s_versions := ["v1.35", "v1.34", "v1.33"]
	every v in supported_k8s_versions{
		not startswith(version, v)
	}
}
