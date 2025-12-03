package armo_builtins

# Check Deployments
deny[msga] {
	deployment := input[_]
	deployment.kind == "Deployment"
	container := deployment.spec.template.spec.containers[i]
	is_nginx_ingress_image(container.image)

	path := sprintf("spec.template.spec.containers[%v].image", [format_int(i, 10)])
	msga := {
		"alertMessage": sprintf("Deployment %v/%v uses ingress-nginx which will reach end-of-life in March 2026. No further releases, bugfixes, or security updates will be provided after that date. Consider migrating to Gateway API or an alternative Ingress controller.", [deployment.metadata.namespace, deployment.metadata.name]),
		"reviewPaths": [path],
		"failedPaths": [path],
		"fixPaths": [],
		"alertObject": {"k8SApiObjects": [deployment]},
	}
}

# Check DaemonSets
deny[msga] {
	daemonset := input[_]
	daemonset.kind == "DaemonSet"
	container := daemonset.spec.template.spec.containers[i]
	is_nginx_ingress_image(container.image)

	path := sprintf("spec.template.spec.containers[%v].image", [format_int(i, 10)])
	msga := {
		"alertMessage": sprintf("DaemonSet %v/%v uses ingress-nginx which will reach end-of-life in March 2026. No further releases, bugfixes, or security updates will be provided after that date. Consider migrating to Gateway API or an alternative Ingress controller.", [daemonset.metadata.namespace, daemonset.metadata.name]),
		"reviewPaths": [path],
		"failedPaths": [path],
		"fixPaths": [],
		"alertObject": {"k8SApiObjects": [daemonset]},
	}
}

# Check StatefulSets
deny[msga] {
	statefulset := input[_]
	statefulset.kind == "StatefulSet"
	container := statefulset.spec.template.spec.containers[i]
	is_nginx_ingress_image(container.image)

	path := sprintf("spec.template.spec.containers[%v].image", [format_int(i, 10)])
	msga := {
		"alertMessage": sprintf("StatefulSet %v/%v uses ingress-nginx which will reach end-of-life in March 2026. No further releases, bugfixes, or security updates will be provided after that date. Consider migrating to Gateway API or an alternative Ingress controller.", [statefulset.metadata.namespace, statefulset.metadata.name]),
		"reviewPaths": [path],
		"failedPaths": [path],
		"fixPaths": [],
		"alertObject": {"k8SApiObjects": [statefulset]},
	}
}

# Helper: Check if image is nginx-ingress
is_nginx_ingress_image(image) {
	contains(image, "ingress-nginx/controller")
}

is_nginx_ingress_image(image) {
	contains(image, "nginx-ingress-controller")
}

is_nginx_ingress_image(image) {
	contains(image, "ingress-controller")
	contains(image, "nginx")
}
