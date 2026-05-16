"""Демо: ещё один секрет в смешанном PR (отдельный файл, чтобы pre-scan
проверил поведение на нескольких источниках)."""

# Уязвимость #4: connection string c inline-паролем (production)
SENTRY_DSN = "https://demo_key:s3ntry_pw_d3mo_x9z@sentry.io/9876543"

# Уязвимость #5: GitHub PAT в виде литерала
RELEASE_BOT_TOKEN = "ghp_RELEASEdemoDEMOdemoDEMOdemoDEMO1234"
