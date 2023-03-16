package armo_builtins

import future.keywords.if

### POD ###

# Fails if securityContext.fsGroupChangePolicy does not have an allowed value
deny[msga] {
    # verify the object kind
    pod := input[_]
    pod.kind = "Pod"
    
    # check securityContext has fsGroupChangePolicy set
    not fsGroupChangePolicySetProperly(pod.spec.securityContext)

    path := "spec.securityContext.fsGroupChangePolicy"
    msga := {
		"alertMessage": sprintf("Pod: %v does not set 'securityContext.fsGroupChangePolicy' with allowed value", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [pod]
		}
    }
}

### WORKLOAD ###

# Fails if securityContext.fsGroupChangePolicy does not have an allowed value
deny[msga] {
    # verify the object kind
    wl := input[_]
    manifest_kind := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
    manifest_kind[wl.kind]
    
    # check securityContext has fsGroupChangePolicy set
    not fsGroupChangePolicySetProperly(wl.spec.template.spec.securityContext)

    path := "spec.template.spec.securityContext.fsGroupChangePolicy"
    msga := {
		"alertMessage": sprintf("Workload: %v does not set 'securityContext.fsGroupChangePolicy' with allowed value", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
    }
}

### CRONJOB ###

# Fails if securityContext.fsGroupChangePolicy does not have an allowed value
deny[msga] {
    # verify the object kind
    cj := input[_]
    cj.kind == "CronJob"

    # check securityContext has fsGroupChangePolicy set
    not fsGroupChangePolicySetProperly(cj.spec.jobTemplate.spec.template.spec.securityContext)

    path := "spec.jobTemplate.spec.template.spec.securityContext.fsGroupChangePolicy"
    msga := {
		"alertMessage": sprintf("CronJob: %v does not set 'securityContext.fsGroupChangePolicy' with allowed value", [cj.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [cj]
		}
    }
}

# fsGroupChangePolicySetProperly checks if applied value is set as appropriate [Always|OnRootMismatch]
fsGroupChangePolicySetProperly(securityContext) := true if {
    regex.match(securityContext.fsGroupChangePolicy, "Always|OnRootMismatch")
} else := false

