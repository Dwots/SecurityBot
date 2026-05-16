"""Демо-конфиг с захардкоженными секретами.

ВНИМАНИЕ: значения **синтетические**, но соответствуют реальным
паттернам провайдеров — pre-scan SunSecurityBot должен их поймать.
"""

# Уязвимость #1: AWS production credentials в коде (pre-scan: aws_access_key_id)
AWS_ACCESS_KEY_ID = "AKIAQ7DEMOX9DEMOX9D2"
AWS_SECRET_ACCESS_KEY = "dEmoFakEsEcREt40CharsWithEntropy+xy/abcDEF12"

# Уязвимость #2: Stripe live mode (pre-scan: stripe_secret)
STRIPE_SECRET_KEY = "sk_live_DEMOdemoDEMOdemoDEMOdemo01XY"

# Уязвимость #3: GitHub Personal Access Token (pre-scan: github_pat)
GITHUB_TOKEN = "ghp_DEMO9876DEMO9876DEMO9876DEMO9876DE12"

# Уязвимость #4: OpenAI key (pre-scan via prefix `sk-`)
OPENAI_API_KEY = "sk-demo9876demo9876demo9876demo9876demo98T3BlbkFJ"

# Уязвимость #5: Multi-line JWT — ловит LLM, не pre-scan
SERVICE_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiJzZXJ2aWNlLWRlbW8iLCJpYXQiOjE3MDAwMDAwMDB9"
    ".synthetic-demo-signature-DO-NOT-USE-IN-PROD"
)

# Уязвимость #6: connection string с inline-паролем
DATABASE_URL = "postgresql://app_user:r3aL_pAssw0rd_d3mo@db.internal.prod.example:5432/payments"
