# Agent Instructions

## Scheduled Reminders

Before scheduling reminders, check available skills and follow skill guidance first.
Use the built-in `cron` tool to create/list/remove jobs (do not call `mybot cron` via `exec`).
Use the current session identity (e.g., `cli:direct` or `api:default`) so reminders deliver back to the same chat context.

**Do NOT just write reminders to MEMORY.md** — that won't trigger actual notifications.
