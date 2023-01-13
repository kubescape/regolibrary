package armo_builtins
import data.kubernetes.api.client as client
import data

deny[msga] {
	wl := input[_]
	wl.kind == "Service"
	wl.spec.type == "LoadBalancer"
}

