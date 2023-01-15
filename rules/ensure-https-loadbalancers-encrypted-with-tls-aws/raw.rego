package armo_builtins
import data.kubernetes.api.client as client
import data

# deny LoadBalancer services that are configured for ssl connection (port: 443), but don't have TLS certificate set.
deny[msga] {

	wl_kind := "Service"
	wl_type := "LoadBalancer"
	wl_required_annotation := "service.beta.kubernetes.io/aws-load-balancer-ssl-cert"

	# filterring LoadBalancers
	wl := 	input[_]
	wl.kind == wl_kind
	wl.spec.type == wl_type	

	#  filterring loadbalancers with port 443.
	wl.spec.ports[_].port == 443

	# filterring annotations without ssl cert confgiured.
	annotations := object.get(wl, ["metadata", "annotations"], [])
	ssl_cert_annotations := [annotations[i] | annotation = i; startswith(i, wl_required_annotation)]
	count(ssl_cert_annotations) == 0

	# prepare message data.
	alert_message :=  sprintf("LoadBalancer '%v' has no TLS configured", [wl.metadata.name])
	failed_paths := [sprintf("metadata.annotations['%v']", [wl_required_annotation])]
	fixed_paths := [{"path": sprintf("metadata.annotations['%v']", [wl_required_annotation]), "value": "AWS_LOADBALANCER_SSL_CERT"}]

	msga := {
		"alertMessage": alert_message,
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": failed_paths,
		"fixPaths": fixed_paths,
		"alertObject": {
			"k8sApiObjects": [],
            "externalObjects": wl
		}
	}
}

