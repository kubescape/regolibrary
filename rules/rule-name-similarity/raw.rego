package armo_builtins
import data
# import data.cautils as cautils
# import data.kubernetes.api.client as client

# input: pods
# apiversion: v1
# fails if object has similar name to known workload (but is not from that workload)

deny[msga] {
	object := input[_]
	wanted_kinds := {"Pod", "ReplicaSet", "Job"}
	wanted_kinds[object.kind]

	# see default-config-inputs.json for list values
    wl_known_names := data.postureControlInputs.wlKnownNames
    wl_name := wl_known_names[_]
    contains(object.metadata.name, wl_name)
	path := "metadata.name"
	
	msga := {
		"alertMessage": sprintf("this %v has a similar name to %v", [object.kind, wl_name]),
		"alertScore": 9,
		"fixPaths": [],
		"failedPaths": [path],
		"packagename": "armo_builtins",
         "alertObject": {
			"k8sApiObjects": [object]
		}
     }
}