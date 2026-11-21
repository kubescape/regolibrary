# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

deny contains msg if {
	maxima := object.get(data.postureControlInputs, "cpu_limit_max", [])
	count(maxima) > 0
	wl := input[_]
	wl.kind == "WorkerPool"
	limit := object.get(wl, ["spec", "template", "resources", "limits", "cpu"], "")
	worker_cpu_limit_invalid(limit, maxima[_])
	msg := worker_ceiling_message(wl, "spec.template.resources.limits.cpu", "CPU")
}

deny contains msg if {
	maxima := object.get(data.postureControlInputs, "memory_limit_max", [])
	count(maxima) > 0
	wl := input[_]
	wl.kind == "WorkerPool"
	limit := object.get(wl, ["spec", "template", "resources", "limits", "memory"], "")
	worker_memory_limit_invalid(limit, maxima[_])
	msg := worker_ceiling_message(wl, "spec.template.resources.limits.memory", "memory")
}

worker_cpu_limit_invalid("", _)

worker_cpu_limit_invalid(limit, maximum) if {
	limit != ""
	worker_cpu_millicores(limit) > worker_cpu_millicores(maximum)
}

worker_memory_limit_invalid("", _)

worker_memory_limit_invalid(limit, maximum) if {
	limit != ""
	worker_memory_bytes(limit) > worker_memory_bytes(maximum)
}

worker_ceiling_message(wl, path, resource) := {"alertMessage": sprintf("Worker Pod %s limit is missing or exceeds the configured ceiling", [resource]), "packagename": "armo_builtins", "failedPaths": [path], "reviewPaths": [path], "fixPaths": [], "alertScore": 7, "alertObject": {"k8sApiObjects": [wl]}}

worker_cpu_millicores(q) := n if {
	s := sprintf("%v", [q])
	endswith(s, "n")
	n := to_number(trim_suffix(s, "n")) / 1000000
} else := n if {
	s := sprintf("%v", [q])
	endswith(s, "u")
	n := to_number(trim_suffix(s, "u")) / 1000
} else := n if {
	s := sprintf("%v", [q])
	endswith(s, "m")
	n := to_number(trim_suffix(s, "m"))
} else := n if {
	s := sprintf("%v", [q])
	endswith(s, "k")
	n := to_number(trim_suffix(s, "k")) * 1000000
} else := n if {
	s := sprintf("%v", [q])
	endswith(s, "M")
	n := to_number(trim_suffix(s, "M")) * 1000000000
} else := n if {
	s := sprintf("%v", [q])
	endswith(s, "G")
	n := to_number(trim_suffix(s, "G")) * 1000000000000
} else := n if {
	s := sprintf("%v", [q])
	endswith(s, "T")
	n := to_number(trim_suffix(s, "T")) * 1000000000000000
} else := n if {
	s := sprintf("%v", [q])
	endswith(s, "P")
	n := to_number(trim_suffix(s, "P")) * 1000000000000000000
} else := n if {
	s := sprintf("%v", [q])
	endswith(s, "E")
	n := to_number(trim_suffix(s, "E")) * 1000000000000000000000
} else := n if {
	n := to_number(q) * 1000
}

worker_memory_bytes(q) := n if {
	s := sprintf("%v", [q])
	endswith(s, "Ki")
	n := to_number(trim_suffix(s, "Ki")) * 1024
} else := n if {
	s := sprintf("%v", [q])
	endswith(s, "Mi")
	n := to_number(trim_suffix(s, "Mi")) * 1048576
} else := n if {
	s := sprintf("%v", [q])
	endswith(s, "Gi")
	n := to_number(trim_suffix(s, "Gi")) * 1073741824
} else := n if {
	s := sprintf("%v", [q])
	endswith(s, "Ti")
	n := to_number(trim_suffix(s, "Ti")) * 1099511627776
} else := n if {
	s := sprintf("%v", [q])
	endswith(s, "Pi")
	n := to_number(trim_suffix(s, "Pi")) * 1125899906842624
} else := n if {
	s := sprintf("%v", [q])
	endswith(s, "Ei")
	n := to_number(trim_suffix(s, "Ei")) * 1152921504606846976
} else := n if {
	s := sprintf("%v", [q])
	endswith(s, "k")
	n := to_number(trim_suffix(s, "k")) * 1000
} else := n if {
	s := sprintf("%v", [q])
	endswith(s, "K")
	n := to_number(trim_suffix(s, "K")) * 1000
} else := n if {
	s := sprintf("%v", [q])
	endswith(s, "M")
	n := to_number(trim_suffix(s, "M")) * 1000000
} else := n if {
	s := sprintf("%v", [q])
	endswith(s, "G")
	n := to_number(trim_suffix(s, "G")) * 1000000000
} else := n if {
	s := sprintf("%v", [q])
	endswith(s, "T")
	n := to_number(trim_suffix(s, "T")) * 1000000000000
} else := n if {
	s := sprintf("%v", [q])
	endswith(s, "P")
	n := to_number(trim_suffix(s, "P")) * 1000000000000000
} else := n if {
	s := sprintf("%v", [q])
	endswith(s, "E")
	n := to_number(trim_suffix(s, "E")) * 1000000000000000000
} else := n if {
	s := sprintf("%v", [q])
	endswith(s, "m")
	n := to_number(trim_suffix(s, "m")) / 1000
} else := n if {
	n := to_number(q)
}
