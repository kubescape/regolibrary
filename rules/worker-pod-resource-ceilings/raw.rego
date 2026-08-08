# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

deny contains msg if {
	wl := input[_]
	maxima := object.get(data.postureControlInputs, "cpu_limit_max", [])
	count(maxima) > 0
	limit := object.get(object.get(object.get(object.get(wl.spec, "template", {}), "resources", {}), "limits", {}), "cpu", "")
	worker_cpu_limit_invalid(limit, maxima[0])
	msg := worker_ceiling_message(wl, "spec.template.resources.limits.cpu", "CPU")
}

deny contains msg if {
	wl := input[_]
	maxima := object.get(data.postureControlInputs, "memory_limit_max", [])
	count(maxima) > 0
	limit := object.get(object.get(object.get(object.get(wl.spec, "template", {}), "resources", {}), "limits", {}), "memory", "")
	worker_memory_limit_invalid(limit, maxima[0])
	msg := worker_ceiling_message(wl, "spec.template.resources.limits.memory", "memory")
}

worker_cpu_millicores(quantity) := to_number(trim_suffix(quantity, "m")) if endswith(quantity, "m")
worker_cpu_millicores(quantity) := to_number(quantity) * 1000 if not endswith(quantity, "m")

worker_cpu_limit_invalid(limit, _) if limit == ""

worker_cpu_limit_invalid(limit, maximum) if {
	limit != ""
	worker_cpu_millicores(limit) > worker_cpu_millicores(maximum)
}

worker_memory_limit_invalid(limit, _) if limit == ""

worker_memory_limit_invalid(limit, maximum) if {
	limit != ""
	units.parse_bytes(limit) > units.parse_bytes(maximum)
}

worker_ceiling_message(wl, path, resource) := {"alertMessage": sprintf("Worker Pod %s limit is missing or exceeds the configured ceiling", [resource]), "packagename": "armo_builtins", "failedPaths": [path], "fixPaths": [], "alertScore": 7, "alertObject": {"k8sApiObjects": [wl]}}
