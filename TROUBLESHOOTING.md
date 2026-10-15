# Diagnóstico

- Falha APT/PyPI: verifique conectividade, DNS, proxy e certificados. O instalador pode deixar uma instalação parcial; não a apague sem examinar os arquivos. O atualizador prepara dependências antes de parar o serviço.
- Serviço falha: `sudo journalctl -u rbl-monitor -n 100 --no-pager`. Confira `.env`, permissões de `data/`, porta ocupada e versão Python (3.10 ou superior).
- Caminho personalizado: use sempre os scripts da pasta instalada. O instalador atual não copia fontes: extraia na pasta final e execute ali. Diretórios privados como `/root` impedem acesso de `rblmonitor`; prefira pasta exclusiva em `/opt` ou `/srv`. Não mova a instalação pronta e não altere permissões dos diretórios pais indiscriminadamente.
- Login após atualização da gestão de usuários: sessões antigas são invalidadas uma vez; faça login novamente. Redefinir senha, alterar perfil ou desativar conta também revoga suas sessões.
- SQLite: somente `data/` precisa ser gravável por `rblmonitor`. Nunca copie um banco ativo diretamente: use a API SQLite de backup ou pare o serviço antes de copiar todos os arquivos.
- TIMEOUT/REFUSED/DNS_ERROR: falha de consulta não equivale a listagem. Confira resolvedor e condições de acesso do provedor. Use Retry no par IP/RBL afetado; os horários dos demais resultados são preservados.
- Spamhaus/SpamRATS: informe a chave própria no painel quando necessária. Não coloque chaves em zonas JSON nem em URLs de repositório. Falhas de autorização não devem aparecer como bloqueios.
- RBL desativada: sai dos alertas ativos, mantendo histórico. Ignorar afeta somente o IP/RBL. Encerrar manualmente pode gerar um novo incidente na próxima listagem.
- SMTP: configure host, porta, TLS, remetente e destinatários no painel. Campo senha vazio mantém a anterior. Teste de envio confirma aceitação pelo servidor SMTP, não entrega final na caixa de entrada.
- CSRF: recarregue a página após expiração da sessão. Não desative CSRF para contornar erros.
- Atualização falha: confira o diretório de backup indicado. O rollback tenta recuperar código, Python, serviço e banco. Não restaure backups enquanto o serviço estiver escrevendo.
- HTTPS: com um único proxy confiável, defina `TRUST_PROXY=1` e `COOKIE_SECURE=1` em `.env`; restrinja a porta da aplicação ao proxy. Reinicie o serviço. Por padrão, cabeçalhos encaminhados não são confiados.
- Agendamento duplicado: mantenha Gunicorn com exatamente um worker; múltiplos workers iniciam schedulers independentes.

Antes da produção, valide instalação e rollback em uma VM Ubuntu/Debian de teste, com SMTP e DNS controlados. O pacote não inclui servidor DNS recursivo nem proxy TLS.
