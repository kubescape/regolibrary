package armo_builtins

# fails in case 'Service' object has not 'service.beta.kubernetes.io/azure-load-balancer-internal' annotation.
deny[msga] {
	svc := input[_]
	svc.kind == "Service"
	svc.spec.type == "LoadBalancer"
	not svc.metadata.annotations["service.beta.kubernetes.io/azure-load-balancer-internal"]

	msga := {
    	"alertMessage": "Service object LoadBalancer has not 'service.beta.kubernetes.io/azure-load-balancer-internal' annotation.",
    	"packagename": "armo_builtins",
    	"alertScore": 7,
    	"failedPaths": ["spec.metadata.annotations['service.beta.kubernetes.io/azure-load-balancer-internal']"],
    	"fixPaths":[],
        "fixCommand": "",
    	"alertObject": {
			"k8sObject": [svc]
        }
    }
}

# fails in case 'Service' object has annotation 'service.beta.kubernetes.io/azure-load-balancer-internal' != 'true'.
deny[msga] {
	svc := input[_]
	svc.kind == "Service"
	svc.spec.type == "LoadBalancer"
	svc.metadata.annotations["service.beta.kubernetes.io/azure-load-balancer-internal"] != "true"

	msga := {
    	"alertMessage": "Service object LoadBalancer has annotation 'service.beta.kubernetes.io/azure-load-balancer-internal' != 'true'.",
    	"packagename": "armo_builtins",
    	"alertScore": 7,
    	"failedPaths": ["spec.metadata.annotations['service.beta.kubernetes.io/azure-load-balancer-internal']"],
    	"fixPaths":[],
        "fixCommand": "",
    	"alertObject": {
			"k8sObject": [svc]
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
    	"failedPaths": ["spec.tls"],
    	"fixPaths":[],
        "fixCommand": "",
    	"alertObject": {
			"k8sObject": [ingress]
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

	msga := {
    	"alertMessage": "Ingress object has annotation 'kubernetes.io/ingress.class' != 'azure/application-gateway'.",
    	"packagename": "armo_builtins",
    	"alertScore": 7,
    	"failedPaths": ["spec.metadata.annotations['kubernetes.io/ingress.class']"],
    	"fixPaths":[],
        "fixCommand": "",
    	"alertObject": {
			"k8sObject": [ingress]
        }
    }
}

isTLSSet(spec) {
	count(spec.tls) > 0
}