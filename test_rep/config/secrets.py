"""Hardcoded credentials.

ВНИМАНИЕ: этот файл — namespace для namespace для намеренно
захардкоженных секретов в demo-репо для тестирования SunSecurityBot.
Все значения — СИНТЕТИЧЕСКИЕ, сгенерированы случайно, не привязаны
ни к одному live-аккаунту и не действуют ни в одном сервисе. Подробнее
см. test_rep/README.md §5 «Дисклеймер про секреты».

Production-код должен читать креды из env / secret manager
(см. config/settings.py как пример правильного подхода).
"""
from __future__ import annotations

# VULN HC-1: AWS access key + secret в исходниках (CWE-798, critical).
# Префикс AKIA + 16 uppercase-letters/digits — формат IAM access key id.
AWS_ACCESS_KEY_ID = "AKIA4OIUTCX4SHV81WG1"
AWS_SECRET_ACCESS_KEY = "KuTueKChDWTZM3PbMEHup4/AaCGGqeVNEhEQFAgl"

# VULN HC-2: GitHub Personal Access Token классического формата
# (`ghp_` + 36 base62). Compromise = доступ ко всем репозиториям
# владельца с указанными scope'ами.
GITHUB_PERSONAL_ACCESS_TOKEN = "ghp_fCdBXk5A1jz26LGvi1dDiKM1US6NmVqkc9BR"

# VULN HC-3: Stripe live secret key (`sk_live_` + 24+ base62).
# Compromise = полный API-доступ к платежам / refund'ам / customer-data.
STRIPE_SECRET_KEY = "sk_live_KAzcrIvLkUdmse1HTzKQVpOc"

# VULN HC-4: JWT-токен сервисного аккаунта (HS256 header.payload.signature).
# Compromise = аутентификация как этот сервис до истечения exp.
SERVICE_JWT = (
    "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9."
    "eyJzdWIiOiAidXNyXzQxOTgiLCAiaWF0IjogMTcxNTAwMDAwMCwgInJvbGUiOiAiYWRtaW4ifQ."
    "RkqzkHkzy74FfsQZPPr6z9wxlZxBAtryGqRLtpeoLNl"
)
