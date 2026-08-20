# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

deny contains msga if {
	template := input[_]
	template.kind == "SandboxTemplate"

	container := template.spec.podTemplate.spec.containers[i]
	not container.resources.limits.memory

	fixPaths := [{"path": sprintf("spec.podTemplate.spec.containers[%v].resources.limits.memory", [format_int(i, 10)]), "value": "YOUR_VALUE"}]

	msga := {
		"alertMessage": sprintf("SandboxTemplate '%v' container '%v' does not have memory limits set.", [template.metadata.name, container.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": fixPaths,
		"alertObject": {
			"k8sApiObjects": [template],
		},
	}
}

deny contains msga if {
	template := input[_]
	template.kind == "SandboxTemplate"

	container := template.spec.podTemplate.spec.containers[i]
	memory_limit := container.resources.limits.memory

	sandbox_memory_limit_max := data.postureControlInputs.sandbox_memory_limit_max[_]
	mem_to_bytes(memory_limit) > mem_to_bytes(sandbox_memory_limit_max)

	failed_path := sprintf("spec.podTemplate.spec.containers[%v].resources.limits.memory", [format_int(i, 10)])

	msga := {
		"alertMessage": sprintf("SandboxTemplate '%v' container '%v' memory limit '%v' exceeds the configured maximum '%v'.", [template.metadata.name, container.name, memory_limit, sandbox_memory_limit_max]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [failed_path],
		"fixPaths": [],
		"reviewPaths": [failed_path],
		"alertObject": {
			"k8sApiObjects": [template],
		},
	}
}

mem_to_bytes(q) := n if {
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
