permit (
    principal is AegisAI::User,
    action == AegisAI::Action::"ReadKnowledgeBase",
    resource is AegisAI::KnowledgeBase
)
when {
    principal.department == resource.ownerDepartment &&
    principal.clearanceLevel >= resource.classificationLevel
};
