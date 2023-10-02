package armo_builtins

deny[msga] {
  services := [ x | x = input[_]; x.kind == "Service" ]
  pods     := [ x | x = input[_]; x.kind == "Pod" ]
  vulns    := [ x | x = input[_]; x.kind == "ImageVulnerabilities"]

  pod     := pods[_]
  service := services[_]
  vuln    := vulns[_]

  # vuln data is relevant 
  count(vuln.data) > 0 

  # service is external-facing
  filter_external_access(service)

  # pod has the current service
  service_to_pod(service, pod) > 0

  # get container image name
  container := pod.spec.containers[i]

  # image has vulnerabilities
  
  container.image == vuln.metadata.name

  # At least one critical vulnerabilities
  filter_critical_vulnerabilities(vuln)

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

filter_critical_vulnerabilities(vuln) {
  data := vuln.data[_]
  data.severity == "Critical"
}

filter_external_access(service) {
  service.spec.type != "ClusterIP"
}

service_to_pod(service, pod) = res {
  # Make sure we're looking on the same namespace
  service.metadata.namespace == pod.metadata.namespace

  service_selectors := [ x | x = service.spec.selector[_] ]

  res := count([ x | x = pod.metadata.labels[_]; x == service_selectors[_] ])
}