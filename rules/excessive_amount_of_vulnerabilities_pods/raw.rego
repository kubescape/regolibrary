package armo_builtins

deny[msga] {
  pods    := [ x | x = input[_]; x.kind == "Pod" ]
  vulns   := [ x | x = input[_]; x.kind == "ImageVulnerabilities"]

  pod     := pods[_]
  vuln    := vulns[_]

  # vuln data is relevant
  count(vuln.data) > 0

  # get container image name
  container := pod.spec.containers[i]

  # image has vulnerabilities
  container.image == vuln.metadata.name

  # Has ^ amount of vulnerabilities
  check_num_vulnerabilities(vuln)

  related_objects := [pod, vuln]

  path := sprintf("status.containerStatuses[%v].imageID", [format_int(i, 10)])

  metadata = {
  	"name": pod.metadata.name,
  	"namespace": pod.metadata.namespace
  }

  external_objects = {
  	"apiVersion": "result.vulnscan.com/v1",
  	"kind": pod.kind,
  	"metadata": metadata,
  	"relatedObjects": related_objects
  }

  msga := {
  	"alertMessage": sprintf("pod '%v' exposed with critical vulnerabilities", [pod.metadata.name]),
  	"packagename": "armo_builtins",
  	"alertScore": 7,
    "reviewPaths": [path],
  	"failedPaths": [path],
  	"fixPaths": [],
  	"alertObject": {
      "externalObjects": external_objects
  	}
  }
}

check_num_vulnerabilities(vuln) {
  exists := count([ x | x = vuln.data[_]; x.severity == "Critical" ])

  str_max := data.postureControlInputs.max_critical_vulnerabilities[_]
  exists > to_number(str_max)
}

check_num_vulnerabilities(vuln) {
  exists := count([ x | x = vuln.data[_]; x.severity == "High" ])

  str_max := data.postureControlInputs.max_high_vulnerabilities[_]
  exists > to_number(str_max)
}