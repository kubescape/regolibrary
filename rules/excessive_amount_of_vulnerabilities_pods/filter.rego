# regal ignore:directory-package-mismatch 
package armo_builtins

import rego.v1

deny contains msga if {
	pods := [x | x = input[_]; x.kind == "Pod"]
	vulns := [x | x = input[_]; x.kind == "ImageVulnerabilities"]

	pod := pods[_]
	vuln := vulns[_]

	# vuln data is relevant
	count(vuln.data) > 0

	# get container image name
	container := pod.spec.containers[i]

	# image has vulnerabilities
	container.image == vuln.metadata.name

	metadata = {
		"name": pod.metadata.name,
		"namespace": pod.metadata.namespace,
	}
    related_objects := [pod, vuln]

	external_objects = {
		"apiVersion": "result.vulnscan.com/v1",
		"kind": pod.kind,
		"metadata": metadata,
		"relatedObjects": related_objects,
	}

	path := sprintf("status.containerStatuses[%v].imageID", [format_int(i, 10)])

	msga := {
		"alertMessage": sprintf("pod '%v' exposed with critical vulnerabilities", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
		"fixPaths": [],
		"alertObject": {"externalObjects": external_objects},
	}
}
