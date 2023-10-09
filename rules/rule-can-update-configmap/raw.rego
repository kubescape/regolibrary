package armo_builtins

import data.cautils

# Fails if user can modify all configmaps, or if he can modify the 'coredns' configmap (default for coredns)
# RoleBinding to Role
deny [msga] {
     configmaps := [configmap | configmap = input[_]; configmap.kind == "ConfigMap"]
     configmap := configmaps[_]
     configmap.metadata.name == "coredns"

    roles := [role |  role= input[_]; role.kind == "Role"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]
    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[_]

    canModifyConfigMapResource(rule)
    canModifyConfigMapVerb(rule)

    rolebinding.roleRef.kind == "Role"
    rolebinding.roleRef.name == role.metadata.name
    rolebinding.metadata.namespace == "kube-system"


    subject := rolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])

    	msga := {
	     "alertMessage": sprintf("The following %v: %v can modify 'coredns' configmap", [subject.kind, subject.name]),
		"alertScore": 6,
		"deletePaths": [path],
         "failedPaths": [path],
		"packagename": "armo_builtins",
          "alertObject": {
			"k8sApiObjects": [role,rolebinding],
			"externalObjects": {
				"subject" : [subject]
			}
		}
     }
}


# Fails if user can modify all configmaps, or if he can modify the 'coredns' configmap (default for coredns)
# RoleBinding to ClusterRole
deny[msga] {
     configmaps := [configmap | configmap = input[_]; configmap.kind == "ConfigMap"]
     configmap := configmaps[_]
     configmap.metadata.name == "coredns"

    roles := [role |  role= input[_]; role.kind == "ClusterRole"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]
    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[_]
    canModifyConfigMapResource(rule)
    canModifyConfigMapVerb(rule)

    rolebinding.roleRef.kind == "ClusterRole"
    rolebinding.roleRef.name == role.metadata.name
    rolebinding.metadata.namespace == "kube-system"



    subject := rolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])

    	msga := {
	     "alertMessage": sprintf("The following %v: %v can modify 'coredns' configmap", [subject.kind, subject.name]),
		"alertScore": 6,
         "failedPaths": [path],
		"packagename": "armo_builtins",
          "alertObject": {
			"k8sApiObjects": [role,rolebinding],
			"externalObjects": {
				"subject" : [subject]
			}
		}
     }

}


# Fails if user can modify all configmaps, or if he can modify the 'coredns' configmap (default for coredns)
# ClusterRoleBinding to ClusterRole
deny[msga] {
    configmaps := [configmap | configmap = input[_]; configmap.kind == "ConfigMap"]
     configmap := configmaps[_]
     configmap.metadata.name == "coredns"

    roles := [role |  role= input[_]; role.kind == "ClusterRole"]
    clusterrolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "ClusterRoleBinding"]
    role:= roles[_]
    clusterrolebinding := clusterrolebindings[_]

    rule:= role.rules[_]
    canModifyConfigMapResource(rule)
    canModifyConfigMapVerb(rule)


    clusterrolebinding.roleRef.kind == "ClusterRole"
    clusterrolebinding.roleRef.name == role.metadata.name



    subject := clusterrolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])

    	msga := {
	     "alertMessage": sprintf("The following %v: %v can modify 'coredns'  configmap", [subject.kind, subject.name]),
		"alertScore": 6,
         "failedPaths": [path],
		"packagename": "armo_builtins",
          "alertObject": {
			"k8sApiObjects": [role,clusterrolebinding],
			"externalObjects": {
				"subject" : [subject]
			}
		}
     }
}





  canModifyConfigMapResource(rule) {
        not rule.resourceNames
       cautils.list_contains(rule.resources,"configmaps")
  }

  canModifyConfigMapResource(rule) {
       not rule.resourceNames
       is_api_group(rule)
       cautils.list_contains(rule.resources,"*")
  }

   canModifyConfigMapResource(rule) {
       cautils.list_contains(rule.resources,"configmaps")
       cautils.list_contains(rule.resourceNames,"coredns")
   }

   canModifyConfigMapVerb(rule) {
       cautils.list_contains(rule.verbs,"update")
   }


   canModifyConfigMapVerb(rule) {
       cautils.list_contains(rule.verbs,"patch")
   }

      canModifyConfigMapVerb(rule) {
       cautils.list_contains(rule.verbs,"*")
   }


is_api_group(rule) {
	apiGroup := rule.apiGroups[_]
	apiGroup == "*"
}

is_api_group(rule) {
	apiGroup := rule.apiGroups[_]
	apiGroup == ""
}