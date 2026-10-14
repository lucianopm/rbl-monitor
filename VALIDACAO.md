# Validação da entrega — 13/10/2026

## Atualização v1.1.0

18 testes automatizados passaram na versão atual, incluindo paginação independente dos eventos, preservação da última verificação e recuperação de senha com preservação de dados. Sintaxe JavaScript do painel e Bash dos scripts conferidas. A seleção main/dev utiliza o mesmo fluxo de backup/rollback e salva o canal após sucesso. Troca completa de canal, timer e instalação Linux não foram executados neste ambiente; exigem homologação. Este relatório mantém abaixo o registro da consolidação inicial.

## Origem e consolidação

Base: `rbl-monitor-consolidado (7).zip`, SHA-256
`6d4e3e2d7146902c67becc4991c036be82362772fe03e4c8277b684c13563034`.
Este ZIP já contém os incrementos de rDNS/FCrDNS, SMTP, histórico, alertas e retry por IP/RBL. Não foram sobrepostos os ZIPs antigos de arquitetura diferente. Fontes sincronizadas do projeto foram preservadas.

## Correções nesta entrega

- Instalação recusa versões existentes em vez de apagar banco, usuários e histórico.
- Gunicorn invocado por `python -m gunicorn`, evitando caminhos absolutos inválidos após troca de virtualenv.
- Permissões de leitura/execução do runtime para o usuário do serviço, mantendo dados privados.
- Atualização usa lock, valida destinos locais e rejeita symlinks; permite `.env.example` sem aceitar `.env` real.
- Backup SQLite adicional com serviço parado; rollback tenta restaurar banco, código, Python e unidade systemd.
- `/health` verifica leitura das tabelas SQLite e retorna 503 em falha.
- Cabeçalhos de proxy só são confiados com `TRUST_PROXY=1`.
- Exemplo de ambiente, regras Git, troubleshooting, testes reproduzíveis e timer opcional.

## Testes realizados

14 testes automatizados passaram com Python 3.12, Flask 3.1.3, Flask-WTF 1.3.0, dnspython 2.9.0 e tzdata 2026.5:
rotas públicas e administrativas, CSRF, compilação de todos os templates, DNSBL listado/limpo/timeout, erro Spamhaus, rDNS/FCrDNS, manutenção de incidente em falha DNS, desativação/ignore, encerrar/reativar alertas, retry somente no alvo preservando o horário das outras RBLs, falha de health, horário brasileiro e sequência SMTP STARTTLS antes de autenticação.

Os testes usam SQLite temporário, IP de documentação `192.0.2.10`, domínios `example.com`, credenciais sintéticas de teste e DNS/SMTP simulados. Não consultam IPs reais nem enviam e-mail.

Sintaxe dos três scripts Bash verificada com `bash -n`; ajuda de instalação/atualização executada. Sintaxe Python e JSON e integridade CRC do ZIP conferidas. Dependências para os testes foram obtidas do PyPI; não há indisponibilidade de PyPI nesta validação.

Para reproduzir em ambiente isolado:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python tests/test_monitor.py
bash -n install.sh update.sh enable-auto-update.sh
```

## Varredura e arquivos excluídos

Inspeção de todos os arquivos de origem e finais: padrões de chaves privadas, tokens comuns, atribuições de senha/segredo, URLs com credenciais, e-mails, IPs e nomes de arquivos de runtime.
Nenhuma credencial real ou dado de produção identificado. Referências públicas de provedores, endereços de loopback/códigos DNSBL e dados sintéticos dos testes foram mantidos.

Nenhum arquivo de produção precisou ser removido do ZIP anexado: ele já não continha bancos, `.env` real, chaves, backups ou logs. Caches `__pycache__` gerados pela validação local foram excluídos da distribuição final. Dependências e arquivos temporários de teste ficam fora do ZIP. O segredo padrão literal do bootstrap foi retirado; a aplicação gera o segredo local quando necessário.

## Limitações

Não foi executada instalação completa em Ubuntu/Debian, serviço systemd, Gunicorn em Linux, timer nem atualização/rollback de ponta a ponta. O ambiente é Windows sem WSL instalado. DNS e SMTP reais não foram testados. A sintaxe e revisão dos scripts não comprovam funcionamento operacional: teste instalação, atualização bem-sucedida e falha forçada em VM de homologação antes da produção.

Rollback descarta gravações realizadas no banco durante a versão nova. Configuração e banco devem permanecer no layout padrão `/opt/rbl-monitor`; não altere `RBL_MONITOR_DB` para outro caminho com este atualizador. `config.json` e `rbls.json` locais são preservados e mudanças remotas nesses arquivos precisam de revisão manual. Arquivos retirados de futuras versões do Git não são automaticamente removidos do servidor. O script não fixa versões exatas nem verifica assinatura de commit: use origem e branch protegidas e confirme compatibilidade das dependências antes de automatizar.

Segredos SMTP e de provedores configurados pelo painel ficam no banco em texto claro e também nos backups protegidos. Uma varredura textual não constitui prova matemática de ausência de segredos. Não houve publicação no GitHub.
