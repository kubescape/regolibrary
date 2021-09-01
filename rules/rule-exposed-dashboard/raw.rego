package armo_builtins

# input: pods
# apiversion: v1
# fails if dashboard exists and is exposed

deny[msga] {
	deployment := input[_]
    startswith(deployment.metadata.name, "kubernetes-dashboard")
    container := deployment.spec.template.spec.containers[_]
    version := trim_prefix(container.image, "kubernetesui/dashboard:v")
    to_number(replace(version, ".", "")) < 201
    
	service := input[_]
	service.kind == "Service"
	isNodePortLbService(service)
    count({x | service.spec.selector[x]; deployment.metadata.labels[x]}) == count(service.spec.selector)

	msga := {
		"alertMessage": sprintf("dashboard exists and is exposed %s", [container.image]),
		"alertScore": 9,
		"packagename": "armo_builtins",
         "alertObject": {
			"k8sApiObjects": [deployment]
		}
     }
}



isNodePortLbService(service) {
	service.spec.type == "NodePort"
}

isNodePortLbService(service) {
	service.spec.type == "LoadBalancer"
}