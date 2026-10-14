# Alterações

## v1.2.0 — 13/10/2026

- Licença permissiva personalizada com referência visível obrigatória ao projeto original no rodapé/créditos.
- LICENSE incluído na instalação, documentação e pacote rbl-monitor.zip.
- Capturas do painel sem IPs identificáveis no README.
- Todas as melhorias de dashboard, paginação, canais main/dev e recuperação de senha incluídas.

## v1.1.0 — 13/10/2026

- Indicadores clicáveis e filtro de erros de RBL, rDNS e FCrDNS.
- Ordem inicial LISTED → ERRO → CLEAN; paginação de 10, 20 ou 50 IPs.
- Histórico e episódios recolhidos, com 15 eventos por página.
- Rodapé com nome e link GitHub.
- Spamhaus ZEN desabilitada por padrão em instalações novas.
- Permissões root:rblmonitor para código e runtime, rblmonitor:rblmonitor para dados; segredos restritos ao root.
- Origem Git oficial por padrão; seleção persistente de main/dev com --main/--dev.
- Redefinição administrativa via CLI com backup consistente SQLite.
- Documentação revisada e 18 testes automatizados.

## v1.0.0

Primeira versão consolidada. Substituída pelo release v1.1.0.
