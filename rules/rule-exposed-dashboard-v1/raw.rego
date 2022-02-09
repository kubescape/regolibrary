package armo_builtins

# input: deployment, service
# apiversion: v1
# fails if dashboard exists and is exposed

deny[msga] {
	deployment := input[_]
	startswith(deployment.metadata.name, "kubernetes-dashboard")
	container := deployment.spec.template.spec.containers[j]
	version := trim_prefix(container.image, "kubernetesui/dashboard:v")
	to_number(replace(version, ".", "")) < 201
	
	service := input[_]
	service.kind == "Service"
	isNodePortLbService(service)
	count({x | service.spec.selector[x]; deployment.metadata.labels[x]}) == count(service.spec.selector)
	path := sprintf("spec.template.spec.containers[%v]", [format_int(j, 10)])

	deploymentvector = {"name": deployment.metadata.name,
						"namespace": deployment.metadata.namespace,
						"kind": deployment.kind,
						"relatedObjects": [service]}

	msga := {
		"alertMessage": sprintf("dashboard exists and is exposed %s", [container.image]),
		"alertScore": 9,
		"fixPaths": [],
		"failedPaths": [path],
		"packagename": "armo_builtins",
		"alertObject": {
			"k8sApiObjects": [],
			"externalObjects": deploymentvector
		}
	}
}



isNodePortLbService(service) {
	service.spec.type == "NodePort"
}

isNodePortLbService(service) {
	service.spec.type == "LoadBalancer"
}