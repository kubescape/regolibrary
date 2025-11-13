package armo_builtins

_builtin_safe_sysctl(name) {
	# NOTE: This set mirrors Kubernetes' safe sysctls. During each
	# Armo/Kubescape release, compare it with the upstream list in
	# pkg/kubelet/sysctl/safe_sysctls.go and update any changes.
	builtin_safe_sysctls := {
		"kernel.shm_rmid_forced",
		"net.ipv4.ip_local_port_range",
		"net.ipv4.tcp_syncookies",
		"net.ipv4.ping_group_range",
		"net.ipv4.ip_unprivileged_port_start",
		"net.ipv4.ip_local_reserved_ports",
		"net.ipv4.tcp_keepalive_time",
		"net.ipv4.tcp_fin_timeout",
		"net.ipv4.tcp_keepalive_intvl",
		"net.ipv4.tcp_keepalive_probes",
		"net.ipv4.tcp_rmem",
		"net.ipv4.tcp_wmem",
	}
	builtin_safe_sysctls[name]
}

safe_sysctl(name) {
	_builtin_safe_sysctl(name)
}

_deny_sysctls_msg(kind_label, obj, sysctls, path) = msga {
	count(sysctls) > 0
	unsafe_sysctls := [sysctl.name |
		sysctl := sysctls[_]
		name := sysctl.name
		not safe_sysctl(name)
	]
	count(unsafe_sysctls) > 0

	msga := {
		"alertMessage": sprintf("%s: %v sets unsafe sysctl(s): %v", [kind_label, obj.metadata.name, unsafe_sysctls]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
		"fixPaths": [{"path": path, "value": "REMOVE_UNSAFE_SYSCTLS"}],
		"alertObject": {"k8sApiObjects": [obj]},
	}
}

### POD ###

# Fails if securityContext.sysctls contains values outside the safe list
deny[msga] {
	# verify the object kind
	pod := input[_]
	pod.kind == "Pod"

	sysctls := pod.spec.securityContext.sysctls
	path := "spec.securityContext.sysctls"
	msga := _deny_sysctls_msg("Pod", pod, sysctls, path)
}

### WORKLOAD ###

# Fails if securityContext.sysctls contains values outside the safe list
deny[msga] {
	# verify the object kind
	wl := input[_]
	manifest_kind := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
	manifest_kind[wl.kind]

	sysctls := wl.spec.template.spec.securityContext.sysctls
	path := "spec.template.spec.securityContext.sysctls"
	msga := _deny_sysctls_msg("Workload", wl, sysctls, path)
}

### CRONJOB ###

# Fails if securityContext.sysctls contains values outside the safe list
deny[msga] {
	# verify the object kind
	cj := input[_]
	cj.kind == "CronJob"

	sysctls := cj.spec.jobTemplate.spec.template.spec.securityContext.sysctls
	path := "spec.jobTemplate.spec.template.spec.securityContext.sysctls"
	msga := _deny_sysctls_msg("CronJob", cj, sysctls, path)
}
