permit (
    principal is AegisAI::User,
    action == AegisAI::Action::"InvokeModel",
    resource is AegisAI::Model
)
when {
    principal.department == resource.ownerDepartment &&
    principal.clearanceLevel >= resource.classificationLevel &&
    principal.allowedModels.contains(resource.modelId)
};
