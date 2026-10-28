# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

# Fails if a container mounts a writable volume without the noexec bind
# mount option (KEP-5855 VolumeBindMountOptions). A writable mount without
# noexec lets an attacker drop a binary, chmod +x and execute it even under
# readOnlyRootFilesystem. Covers containers, initContainers and
# ephemeralContainers across Pods, templated workloads and CronJobs.
# Effectively read-only mounts are exempt: an explicit mount readOnly as
# well as inherently read-only sources (configMap, secret, projected,
# downwardAPI) that kubelet never mounts writable. Explicitly Windows
# workloads are exempt: noexec has no effect on Windows. MountPaths listed
# in postureControlInputs.mountAllowList are exempt. hostPath-backed mounts
# score higher: a writable hostPath without noexec is a node-escape vector.

deny contains msga if {
	wl := input[_]
	specinfo := workload_spec(wl)
	podspec := specinfo.podspec
	prefix := specinfo.prefix
	not is_windows_workload(podspec)
	listname := ["containers", "initContainers", "ephemeralContainers"][_]
	container := podspec[listname][i]
	mount := container.volumeMounts[k]
	not is_effectively_readonly(podspec, mount)
	not allowlisted_mount(mount.mountPath)
	not has_noexec_option(mount)
	score := mount_score(podspec, mount)

	msga := {
		"alertMessage": sprintf("container %v in %v %v mounts %v without the noexec bind mount option", [container.name, wl.kind, wl.metadata.name, mount.mountPath]),
		"packagename": "armo_builtins",
		"alertScore": score,
		"failedPaths": [],
		"fixPaths": [{"path": sprintf("%v%v[%v].volumeMounts[%v].bindMountOptions", [prefix, listname, i, k]), "value": "YOUR_VALUE"}],
		"alertObject": {"k8sApiObjects": [wl]},
	}
}

workload_spec(wl) := {"podspec": wl.spec, "prefix": "spec."} if {
	wl.kind == "Pod"
}

workload_spec(wl) := {"podspec": wl.spec.template.spec, "prefix": "spec.template.spec."} if {
	{"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job"}[wl.kind]
}

workload_spec(wl) := {"podspec": wl.spec.jobTemplate.spec.template.spec, "prefix": "spec.jobTemplate.spec.template.spec."} if {
	wl.kind == "CronJob"
}

allowlisted_mount(mountpath) if {
	mountpath == data.postureControlInputs.mountAllowList[_]
}

# A mount is effectively read-only when the mount itself is read-only or
# when its source volume is one kubelet never mounts writable. The source
# attribute dominates: an explicit readOnly: false on a configMap mount
# does not make it writable.
is_effectively_readonly(podspec, mount) if {
	mount.readOnly == true
}

is_effectively_readonly(podspec, mount) if {
	volume := podspec.volumes[_]
	volume.name == mount.name
	readonly_volume_source(volume)
}

readonly_volume_source(volume) if {
	volume.configMap
}

readonly_volume_source(volume) if {
	volume.secret
}

readonly_volume_source(volume) if {
	volume.projected
}

readonly_volume_source(volume) if {
	volume.downwardAPI
}

# noexec is Linux-only: skip workloads explicitly scheduled to Windows via
# nodeSelector or the pod-level os field.
is_windows_workload(podspec) if {
	podspec.nodeSelector["kubernetes.io/os"] == "windows"
}

is_windows_workload(podspec) if {
	podspec.os.name == "windows"
}

has_noexec_option(mount) if {
	mount.bindMountOptions[_] == "noexec"
}

mount_score(podspec, mount) := 9 if {
	is_hostpath_mount(podspec, mount)
}

mount_score(podspec, mount) := 7 if {
	not is_hostpath_mount(podspec, mount)
}

is_hostpath_mount(podspec, mount) if {
	volume := podspec.volumes[_]
	volume.name == mount.name
	volume.hostPath
}
