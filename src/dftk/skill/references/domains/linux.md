# Linux / server

Evidence may come from authentication logs, account databases, service configuration, shell/history artifacts, package logs, web/application logs, Docker metadata/logs, and filesystem timelines.

Do not substitute account creation metadata for login events. For remote IP claims, prefer authentication/access events with account/session context. For installation time, prefer package-manager/event records over generic file mtimes.

Container evidence requires separating host, image, container instance, and application-layer identities.
