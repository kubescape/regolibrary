package armo_builtins
import data.kubernetes.api.client as client
import data

# deny LoadBalancer services that are configured for ssl connection (port: 443), but don't have TLS certificate set.
deny[msga] {

	# filterring LoadBalancers with port 443.
	service := 	input[_]
	service.kind == "Service"
	service.spec.type == "LoadBalancer"
	service.spec.ports[_].port == 443

	# filterring annotations without ssl cert confgiured.
	annotations := object.get(service, ["metadata", "annotations"], [])
	ssl_cert_annotations := [annotations[i] | annotation = i; startswith(i, "service.beta.kubernetes.io/aws-load-balancer-ssl-cert")]
	count(ssl_cert_annotations) == 0

	msga := {
		"alertMessage": sprintf("LoadBalancer: %v has no TLS configured", [service.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": ["metadata.annotations['service.beta.kubernetes.io/aws-load-balancer-ssl-cert']"],
		"fixPaths":[{"path": "metadata.annotations['service.beta.kubernetes.io/aws-load-balancer-ssl-cert']", "value": "AWS_LOADBALANCER_SSL_CERT"}],
		"alertObject": {
			"k8sApiObjects": [],
            "externalObjects": service
		}
	}
}

