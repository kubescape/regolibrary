package armo_builtins
import data.kubernetes.api.client as client
import data



# deny workloads that doesnt support extrnal service prodvider (secretProviderClass)
deny[msga] {

    wl := input[_]
	wl_kinds := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job", "Pod"}
	wl_kinds[wl.kind]

	not wl.spec.volumes[0].csi.volumeAttributes.secretProviderClass

	# prepare message data.
	alert_message :=  sprintf("%s: %v is not using external secret storage", [wl.kind, wl.metadata.name])
	failed_paths := ["spec.volumes[0].csi.volumeAttributes.secretProviderClass"]
	fixed_paths := []

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

