# RBL Monitor

Aplicação web interna (Flask + SQLite) para verificar endereços IPv4/IPv6 em listas DNSBL/RBL, acompanhar rDNS/FCrDNS, registrar histórico e notificar novos alertas por e-mail.

## Funcionalidades

- Dashboard com IPs, descrições, status operacional, busca/filtros, ordenação e ações em lote.
- Cadastro, edição e exclusão de IPs; verificação automática em intervalos configuráveis e execução manual.
- Consulta paralela de RBLs habilitadas, com classificação de `LISTED`, `CLEAN`, falhas de DNS, timeout e respostas não reconhecidas.
- rDNS (PTR) e FCrDNS (nome PTR resolvendo de volta para o IP original), com suporte a IPv4/IPv6 na validação de identidade.
- Detalhes por IP: resultados, respostas completas, tempos de execução, histórico de verificações, episódios de listagem e observações.
- Tentativa individual da RBL com erro naquele IP, sem repetir as demais RBLs e sem refazer rDNS/FCrDNS. Histórico preservado.
- Nova verificação solicitada por visitantes sem login na página de detalhes, com token CSRF e limites de frequência.
- Administração de listas RBL: habilitação, suporte IPv6, links de delisting, chave SpamRATS e Spamhaus DQS, com salvamento conjunto.
- Classificação das respostas de erro de acesso à Spamhaus ZEN (por exemplo, `127.255.255.254`); APEWS Level 2 desativada por padrão.
- Gestão de alertas por IP/RBL: encerrar manualmente, ignorar, voltar a alertar; desativar uma RBL encerra os alertas operacionais associados, sem apagar o histórico.
- Configuração SMTP por painel (servidor, porta, STARTTLS/SSL/sem TLS, autenticação, remetente, destinatários) e envio de teste.
- Contas de usuário, administrador inicial, proteção CSRF, login e troca de senha.
- Datas na interface em `dd/mm/aaaa HH:mm:ss` no fuso `America/Sao_Paulo`; datas internas são mantidas em UTC.

**Observação:** um registro LISTED é uma resposta da RBL, não um veredito universal de spam. Respostas temporárias de DNS não são consideradas listagens confirmadas. Algumas RBLs exigem acesso pago, chave ou resolvedor DNS próprio.

## Arquitetura simples

- **Servidor:** Gunicorn (uma instância worker), porta TCP **8080**, sem NGINX.
- **Diretório único:** `/opt/rbl-monitor` contém código, templates, arquivos locais, `.venv`, `.env`, `data/monitor.db`, `backups` e o script de atualização.
- **systemd:** é necessário somente um link de registro do serviço em `/etc/systemd/system/`.
- **Persistência:** SQLite, sem MySQL/PostgreSQL ou Docker.
- **Requisitos:** Ubuntu/Debian com `systemd`, Python 3.10 ou superior com `venv`, Internet para dependências APT/PyPI, DNS funcional, acesso `sudo`.

## Começar

**Nova instalação (cancela ao encontrar instalação anterior):**

```bash
unzip rbl-monitor-consolidado.zip
cd rbl-monitor
sudo bash install.sh
```

Acesse `http://IP_DO_SERVIDOR:8080/login`. O script exibe a senha inicial `admin` uma única vez.

**Atualizar uma instalação existente a partir do GitHub (após publicar o repositório):**

```bash
sudo bash /opt/rbl-monitor/update.sh --repo https://github.com/ORGANIZACAO/rbl-monitor.git --branch main
```

Use `update.sh` para atualizar. O instalador recusa instalações existentes para preservar banco, usuários e histórico.

## Documentação

| Documento | Conteúdo |
|---|---|
| [INSTALACAO.md](INSTALACAO.md) | Preparação do Linux, instalação limpa, chaves, verificação e erros comuns |
| [USO.md](USO.md) | Cadastro de IPs, RBLs, retry, status, SMTP, rDNS/FCrDNS e permissões |
| [ATUALIZACAO_GIT.md](ATUALIZACAO_GIT.md) | Publicação no GitHub, configuração da origem, atualizações, backup e recuperação |
| [SEGURANCA.md](SEGURANCA.md) | Auditoria do pacote, arquivos sensíveis, acesso interno e cuidados operacionais |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | DNS, SMTP, SQLite, HTTPS, serviço e recuperação |
| [VALIDACAO.md](VALIDACAO.md) | Testes realizados e limitações desta entrega |

## Comandos essenciais

```bash
sudo systemctl status rbl-monitor --no-pager
sudo systemctl restart rbl-monitor
sudo journalctl -u rbl-monitor -n 100 --no-pager
curl -fsS http://127.0.0.1:8080/health
```

Este código é fornecido sem banco SQLite real, credenciais, `.env` ou chaves. A auditoria estática não substitui testes de implantação no seu servidor.
