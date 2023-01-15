package armo_builtins
import data.kubernetes.api.client as client
import data



# deny workloads that doesn't support external service provider (secretProviderClass)
# reference - https://secrets-store-csi-driver.sigs.k8s.io/concepts.html
deny[msga] {

    wl := input[_]
	wl_kinds := {"Pod"}
	wl_kinds[wl.kind]

	not wl.spec.volumes[0].csi.volumeAttributes.secretProviderClass

	# prepare message data.
	alert_message :=  sprintf("%s: %v is not using external secret storage", [wl.kind, wl.metadata.name])
	failed_paths := []
	fixed_paths := [{"path":"spec.volumes[0].csi.volumeAttributes.secretProviderClass", "value":"SECRET_PROVIDER_CLASS_NAME"}]

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

