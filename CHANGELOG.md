# Alterações

## Em desenvolvimento — 15/10/2026

- Menu simplificado; inclusão e verificação de IPs restritas ao painel de IPs.
- Configurações unificadas com categorias e salvamento transacional de RBLs de IP, domínios, SMTP e tempos. Validação completa antes de qualquer gravação; endereços antigos redirecionam para as categorias.

- Área independente de domínios, com consultas pontuais sem persistência do relatório e monitoramento agendado com histórico, episódios e SMTP.
- Inspeção de SPF, DMARC, DKIM e MX; DBL/URIBL/SURBL opcionais, teste de acesso e códigos específicos de cada provedor.
- Limite por conta, proteção CSRF e relatórios sem cache; dependência tldextract com PSL offline.

## v1.3.0 — 14/10/2026

- Versão v1.3.0 visível no rodapé; atualizações Git mostram também canal e commit. VERSION identifica o pacote.

- Instalação no diretório do próprio pacote, sem cópia dos fontes; --path seleciona outro pacote já descompactado.
- Atualizador e agendamento detectam o caminho local, mantendo compatibilidade com instalações em /opt/rbl-monitor.
- Administradores podem alterar perfis, redefinir senhas e excluir outras contas; proteção da última conta administrativa e bloqueio de ações destrutivas sobre si mesmo.
- Tokens individuais de sessão são renovados ao mudar acesso; cookies antigos deixam de autorizar a conta, inclusive após exclusão e reutilização de um ID.

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
