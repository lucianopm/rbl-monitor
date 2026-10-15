# Domínios: monitoramento e consultas pontuais

A área **Domínios**, no menu após o login, é independente do dashboard de IPs. Administradores e operadores podem consultar e cadastrar domínios; somente administradores configuram as listas.

## Dois fluxos

- **Consulta pontual:** informe um domínio próprio ou de terceiros e clique em Analisar agora. Não cadastra monitoramento, não grava domínio/relatório no banco, não produz histórico nem alertas SMTP. O relatório fica na resposta da página, com cache desabilitado. Para acompanhar o domínio depois, cadastre-o separadamente.
- **Adicionar ao monitoramento:** informe domínio, descrição e seletor DKIM opcional. O cadastro não dispara consulta; use Verificar agora ou aguarde o agendamento. Utiliza o mesmo intervalo configurado para os IPs e respeita a opção de verificação ao iniciar. Mantém resultados, histórico de 15 consultas por página e episódios de listagem. É possível pausar, editar e excluir o domínio com seu histórico.

**Verificar todos os domínios**, na área Domínios, inicia uma execução em segundo plano somente para os cadastros ativos, sem incluir domínios de consultas pontuais nem os pausados. O botão mostra quando já existe uma execução manual em andamento; atualize a página para acompanhar datas e resultados. Não é permitido iniciar outro lote enquanto o anterior estiver executando ou antes de 30 segundos da última solicitação. O agendamento automático continua independente.

Informe somente o nome, como example.com ou mail.example.com, sem protocolo, porta, caminho ou endereço de e-mail. Nomes internacionais são convertidos para ASCII/IDNA. IPs e sufixos sem domínio registrável são recusados. A identificação de sufixos usa o snapshot PSL incluído na dependência tldextract, sem baixar listas em cada consulta.

## Listas e condições de acesso

Todas as listas começam desabilitadas. Em **Configurações → Domínios**, habilite apenas as que você tem autorização para usar e confirme as condições de acesso dos provedores. Salve junto com as demais categorias pelo botão **Salvar todas as configurações**:

- [Spamhaus DBL](https://www.spamhaus.org/faqs/domain-blocklist/): usa DQS e a chave protegida já configurada no painel RBLs. Consulta o nome exato informado; não confundir com a ZEN de IPs.
- [URIBL MULTI](https://uribl.com/about.shtml): consulta o domínio registrável; classifica black como LISTED e grey/red como NOTICE.
- [SURBL MULTI](https://surbl.org/lists): consulta o domínio registrável; phishing, malware, abuse e cracked geram LISTED; disposable/click tracker geram NOTICE.

URIBL/SURBL analisam domínios associados a conteúdo/URLs; não constituem uma avaliação universal da reputação do remetente. Resolvedores públicos, volume e modalidade de uso podem exigir outro acesso ou contrato. A ferramenta não contorna restrições.

Antes da consulta real, cada lista habilitada precisa responder corretamente ao seu teste positivo conhecido. Falha de acesso, código desconhecido, falta de chave e timeout aparecem como erro, nunca como domínio limpo. CLEAN significa apenas ausência naquela consulta bem-sucedida. Sem listas habilitadas, o resultado é NOT_CHECKED, não CLEAN.

## DNS e autenticação

SPF e DMARC mostram registros publicados e verificações estruturais básicas. DMARC tenta a política do domínio organizacional somente quando a política do nome exato está ausente, não quando ocorre timeout. Não há avaliação completa de SPF, includes, autorização de IP nem alinhamento de uma mensagem real.

DKIM não tem um seletor padrão universal. Quando o campo fica vazio, a aplicação tenta uma lista limitada: google, selector1, selector2, s1, s2, default, dkim e k1. São até oito consultas TXT, com quatro em paralelo, seguindo CNAMEs pelo resolvedor DNS. Google usa [google por padrão](https://support.google.com/a/answer/174124), Microsoft 365 utiliza [selector1/selector2](https://learn.microsoft.com/en-us/defender-office-365/email-authentication-dkim-configure) e SendGrid usa [s1/s2 por padrão](https://www.twilio.com/docs/sendgrid/ui/account-and-settings/dkim-records); todos podem ter configurações personalizadas.

O relatório informa os seletores localizados e permite expandir todas as tentativas. Sem chave válida nos nomes tentados, o resultado é **INCONCLUSIVE**, não prova de ausência de DKIM. Timeouts e falhas DNS continuam identificados; uma descoberta com falhas em outros nomes é marcada como parcial. Chaves revogadas, tags duplicadas e registros múltiplos não são tratados como chaves válidas.

Se você preencher o seletor, somente ele será consultado, sem tentativas adicionais. Para ter certeza do nome utilizado, obtenha o valor s= do cabeçalho DKIM-Signature de uma mensagem real, verificando também seu domínio d=; detalhes no [RFC 6376](https://datatracker.ietf.org/doc/html/rfc6376). A descoberta não altera nem preenche automaticamente o seletor salvo e não enumera todos os possíveis seletores. A presença da chave não valida assinaturas, alinhamento nem força criptográfica. MX descreve recebimento de e-mail, não reputação de envio.

## Histórico e alertas

Somente domínios monitorados têm histórico. Uma nova listagem confirmada abre um episódio por domínio/lista e, com os alertas SMTP habilitados, entra na fila de envio para os destinatários existentes. Listagens repetidas não duplicam o episódio; erros não encerram uma listagem anterior. Uma resposta CLEAN encerra o episódio. Pausar o domínio ou desabilitar a lista encerra seus episódios operacionais e remove notificações pendentes, preservando os registros históricos.

As consultas manuais têm limite de uma a cada 30 segundos por conta. O agendamento processa os domínios habilitados, sem limite fixo de cadastros: quantidade, latência DNS e cotas do provedor devem ser dimensionadas pelo administrador.

## Segurança, privacidade e troubleshooting

As análises fazem apenas consultas DNS; não abrem páginas ou conexões HTTP nos domínios informados. Dados retornados pelo DNS são escapados na interface. Credenciais DQS não são incluídas nos relatórios nem em mensagens de erro.

Consulta pontual significa ausência de persistência local do domínio/relatório, não anonimato: resolvedores/provedores podem registrar nomes consultados e o navegador mantém a página enquanto aberta. O banco guarda somente o ID da conta e o horário para limitar consultas. Evite registrar corpos de formulários em proxies/APM; use HTTPS, contas individuais e controle de acesso.

ACCESS_ERROR: confira contrato, resolvedor, limite de consultas e teste positivo do provedor. NOT_CONFIGURED: configure DQS em Configurações. TIMEOUT/DNS_ERROR: confira DNS e saída UDP/TCP 53. NOT_CHECKED nas listas: habilite uma lista autorizada. INCONCLUSIVE em DKIM: informe o seletor exato de uma mensagem; os nomes comuns não cobrem todos os provedores. Um domínio não listado pode ter má reputação em Gmail/Outlook: métricas privadas desses provedores não fazem parte desta análise.

Atualizações instalam tldextract pelo requirements.txt e criam tabelas adicionais automaticamente, sem substituir tabelas de IPs. Faça backup antes de atualizar. Não use uma versão antiga para continuar gravando dados após uma migração sem validar compatibilidade.
