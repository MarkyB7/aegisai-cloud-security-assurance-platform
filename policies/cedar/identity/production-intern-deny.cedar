forbid (
    principal is AegisAI::User,
    action,
    resource
)
when {
    principal.role == "Intern" &&
    resource.environment == "production"
};
