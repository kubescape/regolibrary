
package armo_builtins
import data.cautils as cautils

# ================= create/update ===============================

# fails if user has access to create/update rolebindings/clusterrolebindings
# RoleBinding to Role
deny[msga] {
    roles := [role |  role= input[_]; role.kind == "Role"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]

    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[_]
    canCreateUpdateToRoleResource(rule)
    canCreateUpdateToRoleVerb(rule)
  
    rolebinding.roleRef.kind == "Role"
    rolebinding.roleRef.name == role.metadata.name
    subject := rolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])

    	msga := {
		"alertMessage": sprintf("The following %v: %v, can create/update rolebinding/clusterrolebinding", [subject.kind, subject.name]),
		"alertScore": 3,
          "failedPaths": [path],
		"packagename": "armo_builtins",
          "alertObject": {
			"k8sApiObjects": [role, rolebinding],
			"externalObjects": {
				"subject" : [subject]
			}
		}
     }
}

# fails if user has access to create/update rolebindings/clusterrolebindings
# RoleBinding to ClusterRole
deny [msga]{
    roles := [role |  role= input[_]; role.kind == "ClusterRole"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]
    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[_]
    canCreateUpdateToRoleResource(rule)
    canCreateUpdateToRoleVerb(rule)

    rolebinding.roleRef.kind == "ClusterRole"
    rolebinding.roleRef.name == role.metadata.name
    subject := rolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])

  	msga := {
		"alertMessage": sprintf("The following %v: %v, can create/update rolebinding/clusterrolebinding", [subject.kind, subject.name]),
		"alertScore": 3,
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

# fails if user has access to create/update rolebindings/clusterrolebindings
# ClusterRoleBinding to ClusterRole
deny [msga]{
    roles := [role |  role= input[_]; role.kind == "ClusterRole"]
     clusterrolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "ClusterRoleBinding"]
    role:= roles[_]
     clusterrolebinding := clusterrolebindings[_]

    rule:= role.rules[_]
    canCreateUpdateToRoleResource(rule)
    canCreateUpdateToRoleVerb(rule)

    clusterrolebinding.roleRef.kind == "ClusterRole"
    clusterrolebinding.roleRef.name == role.metadata.name
    subject := clusterrolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])

  	msga := {
		"alertMessage": sprintf("The following %v: %v, can create/update rolebinding/clusterrolebinding", [subject.kind, subject.name]),
		"alertScore": 3,
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

# ================= bind ===============================

# fails if user has access to bind clusterroles/roles
# RoleBinding to Role
deny [msga] {
    roles := [role |  role= input[_]; role.kind == "Role"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]

    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[_]

    canBindToRoleResource(rule)
    canBindToRoleVerb(rule)

    rolebinding.roleRef.kind == "Role"
    rolebinding.roleRef.name == role.metadata.name
    subject := rolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])

    	msga := {
		"alertMessage": sprintf("The following %v: %v, can bind roles/clusterroles", [subject.kind, subject.name]),
		"alertScore": 3,
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


# fails if user has access to bind clusterroles/roles
# RoleBinding to ClusterRole
deny [msga]{
    roles := [role |  role= input[_]; role.kind == "ClusterRole"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]
    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[_]
    
    canBindToRoleResource(rule)
    canBindToRoleVerb(rule)

    rolebinding.roleRef.kind == "ClusterRole"
    rolebinding.roleRef.name == role.metadata.name
    subject := rolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])

  msga := {
		"alertMessage": sprintf("The following %v: %v, can bind roles/clusterroles", [subject.kind, subject.name]),
		"alertScore": 3,
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


# fails if user has access to bind clusterroles/roles
# ClusterRoleBinding to ClusterRole
deny [msga]{
    roles := [role |  role= input[_]; role.kind == "ClusterRole"]
     clusterrolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "ClusterRoleBinding"]
    role:= roles[_]
     clusterrolebinding := clusterrolebindings[_]

    rule:= role.rules[_]
     canBindToRoleResource(rule)
    canBindToRoleVerb(rule)

    clusterrolebinding.roleRef.kind == "ClusterRole"
    clusterrolebinding.roleRef.name == role.metadata.name
    subject := clusterrolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])
    	
   msga := {
		"alertMessage": sprintf("The following %v: %v, can bind roles/clusterroles", [subject.kind, subject.name]),
		"alertScore": 3,
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


# ================= escalate ===============================


# fails if user has access to escalate rolebindings/clusterrolebindings
# RoleBinding to Role
deny[msga] {
    roles := [role |  role= input[_]; role.kind == "Role"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]

    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[_]
    canEscalateToRoleResource(rule)
    canEscalateToRoleVerb(rule)
  
    rolebinding.roleRef.kind == "Role"
    rolebinding.roleRef.name == role.metadata.name
    subject := rolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])

    	msga := {
		"alertMessage": sprintf("The following %v: %v, can escalate rolebinding/clusterrolebinding", [subject.kind, subject.name]),
		"alertScore": 3,
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

# fails if user has access to escalate rolebindings/clusterrolebindings
# RoleBinding to ClusterRole
deny [msga]{
    roles := [role |  role= input[_]; role.kind == "ClusterRole"]
    rolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "RoleBinding"]
    role:= roles[_]
    rolebinding := rolebindings[_]

    rule:= role.rules[_]
    canEscalateToRoleResource(rule)
    canEscalateToRoleVerb(rule)

    rolebinding.roleRef.kind == "ClusterRole"
    rolebinding.roleRef.name == role.metadata.name
    subject := rolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])

  	msga := {
		"alertMessage": sprintf("The following %v: %v, can escalate rolebinding/clusterrolebinding", [subject.kind, subject.name]),
		"alertScore": 3,
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

# fails if user has access to escalate rolebindings/clusterrolebindings
# ClusterRoleBinding to ClusterRole
deny [msga]{
    roles := [role |  role= input[_]; role.kind == "ClusterRole"]
     clusterrolebindings := [rolebinding | rolebinding = input[_]; rolebinding.kind == "ClusterRoleBinding"]
    role:= roles[_]
     clusterrolebinding := clusterrolebindings[_]

    rule:= role.rules[_]
    canEscalateToRoleResource(rule)
    canEscalateToRoleVerb(rule)

    clusterrolebinding.roleRef.kind == "ClusterRole"
    clusterrolebinding.roleRef.name == role.metadata.name
    subject := clusterrolebinding.subjects[i]
    path := sprintf("subjects[%v]", [format_int(i, 10)])
    	
  	msga := {
		"alertMessage": sprintf("The following %v: %v, can escalate rolebinding/clusterrolebinding", [subject.kind, subject.name]),
		"alertScore": 3,
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


# ============== escalate =====================

canEscalateToRoleResource(rule){
     cautils.list_contains(rule.resources,"clusterroles")
}

canEscalateToRoleResource(rule){
     cautils.list_contains(rule.resources,"roles")
}

canEscalateToRoleResource(rule){
     isApiGroup(rule)
     cautils.list_contains(rule.resources,"*")
}

canEscalateToRoleVerb(rule) {
       cautils.list_contains(rule.verbs, "escalate")
}

canEscalateToRoleVerb(rule) {
       cautils.list_contains(rule.verbs, "*")
}


# ============== bind =====================

canBindToRoleResource(rule){
     cautils.list_contains(rule.resources,"clusterroles")
}

canBindToRoleResource(rule){
     cautils.list_contains(rule.resources,"roles")
}

canBindToRoleResource(rule){
     isApiGroup(rule)
     cautils.list_contains(rule.resources,"*")
}


canBindToRoleVerb(rule) {
       cautils.list_contains(rule.verbs, "bind")
}

canBindToRoleVerb(rule) {
       cautils.list_contains(rule.verbs, "*")
}

# ============== create/update =====================

canCreateUpdateToRoleResource(rule) {
      cautils.list_contains(rule.resources,"rolebindings")
}

canCreateUpdateToRoleResource(rule) {
      cautils.list_contains(rule.resources,"clusterrolebindings")
}

canCreateUpdateToRoleResource(rule) {
     isApiGroup(rule)
     cautils.list_contains(rule.resources,"*")
}


canCreateUpdateToRoleVerb(rule) {
     cautils.list_contains(rule.verbs, "create")
}

canCreateUpdateToRoleVerb(rule) {
     cautils.list_contains(rule.verbs, "update")
}

canCreateUpdateToRoleVerb(rule) {
     cautils.list_contains(rule.verbs, "patch")
}

canCreateUpdateToRoleVerb(rule) {
     cautils.list_contains(rule.verbs, "*")
}

isApiGroup(rule) {
	apiGroup := rule.apiGroups[_]
	apiGroup == "*"
}

isApiGroup(rule) {
	apiGroup := rule.apiGroups[_]
	apiGroup == "rbac.authorization.k8s.io"
}