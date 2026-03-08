Projeto mínimo para Vercel que:
- valida o GET do webhook da Meta
- recebe o POST bruto da Meta
- repassa o body bruto para o Woll-AI
- preserva headers importantes, inclusive x-hub-signature-256

Variáveis necessárias:
- WOLL_WEBHOOK_URL
- META_VERIFY_TOKEN
