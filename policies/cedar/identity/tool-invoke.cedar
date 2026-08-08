permit (
    principal is AegisAI::User,
    action == AegisAI::Action::"InvokeTool",
    resource is AegisAI::Tool
)
when {
    principal.department == resource.ownerDepartment &&
    principal.clearanceLevel >= resource.classificationLevel &&
    principal.allowedTools.contains(resource.toolId)
};
