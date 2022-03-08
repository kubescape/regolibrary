package armo_builtins

import data.kubernetes.api.client as client
import data

deny[msga] {
  pods     := [ x | x = input[_]; x.kind == "Pod" ]
  vulns    := [ x | x = input[_]; x.kind == "ImageVulnerabilities"]

  pod     := pods[_]
  vuln    := vulns[_]

  # get container image name
  container := pod.spec.containers[i]

  # image has vulnerabilities
  container.image == vuln.metadata.name

  # Has ^ amount of vulnerabilities
  check_num_vulnerabilities(vuln)

  relatedObjects := [pod, vuln]

  path := sprintf("status.containerStatuses[%v].imageID", [format_int(i, 10)])

  metadata = {
  	"name": pod.metadata.name,
  	"namespace": pod.metadata.namespace
  }

  external_objects = {
  	"apiVersion": "result.vulnscan.com/v1",
  	"kind": pod.kind,
  	"metadata": metadata,
  	"relatedObjects": relatedObjects
  }

  msga := {
  	"alertMessage": sprintf("pod '%v' exposed with critical vulnerabilities", [pod.metadata.name]),
  	"packagename": "armo_builtins",
  	"alertScore": 7,
  	"failedPaths": [path],
  	"fixPaths": [],
  	"alertObject": {
      "externalObjects": external_objects
  	}
  }
}

check_num_vulnerabilities(vuln) {
  count(vuln.data) > 0
  match := [ x | x = vuln.data[_]; x.severity == "Critical" ]
  count(match) > data.postureControlInputs.max_critical_vulnerabilities
}

check_num_vulnerabilities(vuln) {
  count(vuln.data) > 0
  match := [ x | x = vuln.data[_]; x.severity == "High" ]
  count(match) > data.postureControlInputs.max_high_vulnerabilities
}