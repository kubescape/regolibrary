package armo_builtins

import future.keywords.if

### POD ###

# Fails if securityContext.fsGroup does not have a values >= 0
deny[msga] {
    # verify the object kind
    pod := input[_]
    pod.kind = "Pod"

    # check securityContext has fsGroup set properly
    not fsGroupSetProperly(pod.spec.securityContext)


    securityContextPath := "spec.securityContext"

    paths := get_paths(pod, securityContextPath)
    

    msga := {
		"alertMessage": sprintf("Pod: %v does not set 'securityContext.fsGroup' with allowed value", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": paths["failedPaths"],
		"fixPaths": paths["fixPaths"],
		"alertObject": {
			"k8sApiObjects": [pod]
		}
    }
}


### CRONJOB ###

# Fails if securityContext.fsGroup does not have a values >= 0
deny[msga] {
    # verify the object kind
    cj := input[_]
    cj.kind == "CronJob"

    # check securityContext has fsGroup set properly
    not fsGroupSetProperly(cj.spec.jobTemplate.spec.template.spec.securityContext)

    securityContextPath := "spec.jobTemplate.spec.template.spec.securityContext"

    paths := get_paths(cj, securityContextPath)
    
    msga := {
		"alertMessage": sprintf("CronJob: %v does not set 'securityContext.fsGroup' with allowed value", [cj.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": paths["failedPaths"],
		"fixPaths": paths["fixPaths"],
		"alertObject": {
			"k8sApiObjects": [cj]
		}
    }
}


### WORKLOAD ###

# Fails if securityContext.fsGroup does not have a values >= 0
deny[msga] {
    # verify the object kind
    wl := input[_]
    manifest_kind := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
    manifest_kind[wl.kind]

    # check securityContext has fsGroup set properly
    not fsGroupSetProperly(wl.spec.template.spec.securityContext)

    path := "spec.template.spec.securityContext"
    paths := get_paths(wl, path)

    msga := {
		"alertMessage": sprintf("Workload: %v does not set 'securityContext.fsGroup' with allowed value", [wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": paths["failedPaths"],
		"fixPaths": paths["fixPaths"],
		"alertObject": {
			"k8sApiObjects": [wl]
		}
    }
}

# fsGroupSetProperly checks if fsGroup has a value >= 0.
fsGroupSetProperly(securityContext) := true if {
    securityContext.fsGroup >= 0
} else := false


has_key(x, k) { _ = x[k] }


get_paths(resources, securityContextPath) := result {  

  # resources.kind == "CronJob"
  # objectPath := ["spec","jobTemplate","spec","template","spec","securityContext", "fsGroup"]
  objectPath := array.concat(split(securityContextPath, "."), ["fsGroup"])
  # objectPath[count(objectPath)] = 
  object.get(resources, objectPath, false)


  # has_key(securityContext, "fsGroup")
  # has_key(object.get(resources, "spec.jobTemplate.spec.template.spec.securityContext", "") , "fsGroup")


  # has_key(resources.spec.jobTemplate.spec.template.spec.securityContext, "fsGroup")
  result = {"failedPaths": [], "fixPaths": [{"path":sprintf("%v.fsGroup", [securityContextPath]), "value": "YOUR_VALUE"}]}
} else = result {
  result = {"failedPaths": [securityContextPath], "fixPaths": []}
}



# get_paths(resources) := result {  
# 	spec_template_spec_patterns := {"Deployment","ReplicaSet","DaemonSet","StatefulSet","Job"}
# 	spec_template_spec_patterns[resources.kind]
#   has_key(resources.spec.template.spec.securityContext, "fsGroup")
#   result = {"failedPaths": [], "fixPaths": []}
# } else := result {
#   result = {"failedPaths": ["spec.template.spec.securityContext"], "fixPaths": []}
# }