# Segurança e publicação do pacote

## Conteúdo público

Este pacote distribui somente código, templates, CSS, JSON genéricos e documentação. **Não inclui:**

- banco SQLite de produção, histórico de IPs monitorados, usuários ou destinatários;
- `.env` real, chaves de sessão, senhas de administrador ou SMTP;
- chaves de API de SpamRATS / Spamhaus DQS;
- arquivos de logs, cache Python, `.venv`, backups ou arquivos temporários;
- repositório `.git` contendo eventuais commits privados.

Há apenas nomes públicos de provedores e URLs públicas de documentação/delisting nos fontes. Chaves são geradas localmente pelo instalador (OpenSSL), não vêm no arquivo ZIP.

Os testes incluem somente dados sintéticos, IP de documentação e valores explicitamente identificados como exclusivos de teste. Nenhum arquivo de produção foi encontrado no ZIP de origem; caches gerados pela validação não integram a entrega. Veja `VALIDACAO.md` para os resultados e limites concretos.

## Cuidados na operação

1. **Não exponha HTTP puro à Internet.** Use rede interna controlada; em redes de confiança variável use HTTPS na borda e restrinja acesso por firewall/VPN.
2. A página de detalhes é pública para quem alcança o serviço na rede. Visitantes podem pedir rechecagens com proteção CSRF e limitação de frequência. Restrinja por firewall se isso não for desejável.
3. `.env` contém o segredo de assinatura de sessão. `data/monitor.db` pode conter senhas de SMTP e chaves de provedores em texto claro (configurações administrativas), além de endereços de e-mail e IPs. Proteja os diretórios e backups.
4. O painel exige autenticação para alterações administrativas. Revise senhas, privilégios e logs de acesso antes de produção.
5. Configure URLs remotas do atualizador somente para repositórios **confiáveis**. O Git fornece arquivos executáveis para o serviço, e publicar um commit malicioso pode comprometer a VM.
6. Mantenha `.env`, banco, backups e credenciais somente no servidor; não envie esses arquivos ao repositório. `.gitignore` ajuda a evitar inclusões acidentais.
7. O atualizador faz backups locais antes de aplicar mudanças; mantenha cópias externas e teste restauração.

## Limites da validação

Foram feitas verificações de conteúdo e sintaxe no pacote. Não é possível provar a inexistência de segredos usando apenas busca textual; revogação e rotação são necessárias caso alguma chave real tenha sido previamente publicada no Git. O teste completo em servidor Ubuntu/Debian com systemd e conexão ao PyPI deve ser executado antes de produção.
