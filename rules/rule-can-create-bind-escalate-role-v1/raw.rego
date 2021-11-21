package armo_builtins
import data.cautils as cautils

# ================= create/update ===============================

# fails if user has access to create/update rolebindings/clusterrolebindings
deny[msga] {
     subjectVector := input[_]
     role := subjectVector.relatedObjects[i]
     rolebinding := subjectVector.relatedObjects[j]
     endswith(subjectVector.relatedObjects[i].kind, "Role")
     endswith(subjectVector.relatedObjects[j].kind, "Binding")

     rule:= role.rules[_]
     canCreateUpdateToRoleResource(rule)
     canCreateUpdateToRoleVerb(rule)

     msga := {
          "alertMessage": sprintf("Subject: %v-%v can create/update rolebinding/clusterrolebinding", [subjectVector.kind, subjectVector.name]),
          "alertScore": 3,
          "packagename": "armo_builtins",
          "alertObject": {
               "k8sApiObjects": [],
               "externalObjects": subjectVector
          }
     }
}


# ================= bind ===============================

# fails if user has access to bind clusterroles/roles
deny [msga] {
     subjectVector := input[_]
     role := subjectVector.relatedObjects[i]
     rolebinding := subjectVector.relatedObjects[j]
     endswith(subjectVector.relatedObjects[i].kind, "Role")
     endswith(subjectVector.relatedObjects[j].kind, "Binding")

     rule:= role.rules[_]
     canBindToRoleResource(rule)
     canBindToRoleVerb(rule)

     msga := {
          "alertMessage": sprintf("Subject: %v-%v can bind roles/clusterroles", [subjectVector.kind, subjectVector.name]),
          "alertScore": 3,
          "packagename": "armo_builtins",
          "alertObject": {
               "k8sApiObjects": [],
               "externalObjects": subjectVector
          }
     }
}

# ================= escalate ===============================

# fails if user has access to escalate rolebindings/clusterrolebindings
deny[msga] {
     subjectVector := input[_]
     role := subjectVector.relatedObjects[i]
     rolebinding := subjectVector.relatedObjects[j]
     endswith(subjectVector.relatedObjects[i].kind, "Role")
     endswith(subjectVector.relatedObjects[j].kind, "Binding")

     rule:= role.rules[_]
     canEscalateToRoleResource(rule)
     canEscalateToRoleVerb(rule)

     msga := {
          "alertMessage": sprintf("Subject: %v-%v can escalate rolebinding/clusterrolebinding", [subjectVector.kind, subjectVector.name]),
          "alertScore": 3,
          "packagename": "armo_builtins",
          "alertObject": {
               "k8sApiObjects": [],
               "externalObjects": subjectVector
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