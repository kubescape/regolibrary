package armo_builtins

# fails in case of 'Services' of type 'LoadBalancer' are not found.
deny[msga] {
	svc := input[_]
	svc.kind == "Service"
	svc.spec.type != "LoadBalancer"

	msga := {
		"alertMessage": "No LoadBalancer service found.",
    	"packagename": "armo_builtins",
    	"alertScore": 7,
    	"failedPaths": [],
    	"fixPaths":[],
		"alertObject": {
			"k8sApiObjects": [svc]
		}
	}
}

# fails in case 'Service' object has not 'service.beta.kubernetes.io/azure-load-balancer-internal' annotation.
deny[msga] {
	svc := input[_]
	svc.kind == "Service"
	svc.spec.type == "LoadBalancer"
	not svc.metadata.annotations["service.beta.kubernetes.io/azure-load-balancer-internal"]
	path := "metadata.annotations[service.beta.kubernetes.io/azure-load-balancer-internal]"

	msga := {
    	"alertMessage": "Service object LoadBalancer has not 'service.beta.kubernetes.io/azure-load-balancer-internal' annotation.",
    	"packagename": "armo_builtins",
    	"alertScore": 7,
    	"failedPaths": [],
    	"fixPaths":[{"path": path, "value": "true"}],
    	"alertObject": {
			"k8sApiObjects": [svc]
        }
    }
}

# fails in case 'Service' object has annotation 'service.beta.kubernetes.io/azure-load-balancer-internal' != 'true'.
deny[msga] {
	svc := input[_]
	svc.kind == "Service"
	svc.spec.type == "LoadBalancer"
	svc.metadata.annotations["service.beta.kubernetes.io/azure-load-balancer-internal"] != "true"
	path := "metadata.annotations[service.beta.kubernetes.io/azure-load-balancer-internal]"

	msga := {
    	"alertMessage": "Service object LoadBalancer has annotation 'service.beta.kubernetes.io/azure-load-balancer-internal' != 'true'.",
    	"packagename": "armo_builtins",
    	"alertScore": 7,
    	"failedPaths": [],
    	"fixPaths":[{"path": path, "value": "true"}],
    	"alertObject": {
			"k8sApiObjects": [svc]
        }
    }
}

# fails in case 'Ingress' object has spec.tls value not set.
deny[msga] {
	svc := input[_]
	svc.kind == "Service"
	svc.spec.type == "LoadBalancer"
	svc.metadata.annotations["service.beta.kubernetes.io/azure-load-balancer-internal"] == "true"

	ingress := input[_]
	ingress.kind == "Ingress"
	not isTLSSet(ingress.spec)

	msga := {
    	"alertMessage": "Ingress object has 'spec.tls' value not set.",
    	"packagename": "armo_builtins",
    	"alertScore": 7,
		"reviewPaths": ["spec.tls"],
    	"failedPaths": ["spec.tls"],
    	"fixPaths":[],
    	"alertObject": {
			"k8sApiObjects": [ingress]
        }
    }
}

# fails in case 'Ingress' object has annotation 'kubernetes.io/ingress.class' != 'azure/application-gateway'.
deny[msga] {
	svc := input[_]
	svc.kind == "Service"
	svc.spec.type == "LoadBalancer"
	svc.metadata.annotations["service.beta.kubernetes.io/azure-load-balancer-internal"] == "true"

	ingress := input[_]
	ingress.kind == "Ingress"
	isTLSSet(ingress.spec)
	ingress.metadata.annotations["kubernetes.io/ingress.class"] != "azure/application-gateway"

	path := "metadata.annotations[kubernetes.io/ingress.class]"

	msga := {
    	"alertMessage": "Ingress object has annotation 'kubernetes.io/ingress.class' != 'azure/application-gateway'.",
    	"packagename": "armo_builtins",
    	"alertScore": 7,
    	"failedPaths": [],
    	"fixPaths":[{"path": path, "value": "azure/application-gateway"}],
        "fixCommand": "",
    	"alertObject": {
			"k8sApiObjects": [ingress]
        }
    }
}

isTLSSet(spec) {
	count(spec.tls) > 0
}
