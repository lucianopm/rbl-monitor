# Manual de uso — RBL Monitor

## Acesso e níveis

O rodapé exibe a versão do pacote. Após atualização pelo Git, mostra também canal (main/dev) e commit, para identificar precisamente o código instalado. Instalações novas por ZIP mostram somente VERSION até a primeira atualização Git. Versões com sufixo `-dev` ainda não foram lançadas como release; não equivalem ao release estável anterior.

Em **Usuários**, administradores podem alterar o perfil de outra conta (Operador/Administrador), redefinir sua senha com confirmação, ativar/desativar e excluir usuários. A exclusão exige confirmação na interface, é definitiva e não apaga IPs, histórico ou observações. Não é permitido excluir/desativar/rebaixar a própria conta por esse painel, nem remover a última conta administrativa ativa. Para a própria senha use **Minha senha**. Alterações de senha, perfil ou estado invalidam sessões antigas da conta afetada. Senhas precisam de pelo menos 10 caracteres; redefinir senha não reativa uma conta desativada (use Ativar).

A página inicial e os detalhes dos IPs podem ser consultados por visitantes. Um visitante também pode solicitar nova verificação de um IP ativo ou uma nova tentativa de uma RBL com erro. Esses pedidos estão protegidos por CSRF e limitados por frequência (global e por IP). Operações de cadastro, configuração e administração exigem autenticação. As opções de ignorar/encerrar alertas exigem administrador.

## Painel de IPs

O painel abre ordenado por LISTED, ERRO e CLEAN, seguidos dos demais estados. Os indicadores filtram a tabela; “Com erros” também inclui problemas de rDNS/FCrDNS, mesmo se houver listagem ativa. “Sem alertas ou erros” exclui falhas técnicas. Um IP pode entrar simultaneamente nas contagens de listagem e erro.

Selecione 10, 20 ou 50 IPs por página (padrão 10). Busca, filtros, mudança de tamanho e ordenação retornam à primeira página. A seleção em lote fica restrita à página visível e é limpa ao ocultar itens. Histórico e episódios nos detalhes começam recolhidos: clique no título para expandir. Cada seção possui paginação independente de 15 eventos, do mais recente para o mais antigo.

1. Faça login e clique em **Adicionar IP**.
2. Informe IPv4/IPv6 e uma descrição; é possível adicionar vários IPs pelas ações em lote.
3. Use a busca e os filtros para localizar IPs por situação e habilitação.
4. **Detalhes** mostra a última verificação, resultados individuais, histórico de episódios de bloqueio e rDNS/FCrDNS.
5. **Verificar novamente** força a consulta completa das RBLs habilitadas mais os testes de identidade DNS.

**Status operacionais:** `LISTED` significa incidente ativo de RBL habilitada e não ignorada; `IGNORADO` representa listagens silenciadas; `SEM ALERTAS` indica resultado DNS anterior listado, mas sem incidente operacional aberto; `CLEAN` significa ausência de listagem confirmada, e `ERRO` representa falhas na verificação. Status de DNS podem não corresponder exatamente ao status operacional de alerta.

## rDNS / FCrDNS

- **rDNS:** busca os PTRs que correspondem ao IP monitorado.
- **FCrDNS:** consulta os registros A (IPv4) ou AAAA (IPv6) dos nomes PTR e verifica se algum resolve para o IP original.
- A ausência de PTR não comprova abuso; um FCrDNS que não fecha pode indicar configuração de DNS inconsistente.
- Resultados e detalhes ficam na página do IP; uma tentativa isolada de RBL reaproveita a última identidade DNS, não faz novo teste PTR.

## RBLs e tratamento de erros

Em **RBLs**, selecione as listas habilitadas, configure eventual suporte IPv6 e os links de delisting; salve tudo no botão único. Chaves de SpamRATS e Spamhaus DQS são opcionais, dependendo das listas usadas. As chaves digitadas não reaparecem no formulário.

`TIMEOUT`, `SERVFAIL`, `REFUSED`, `DNS_ERROR` e outros erros não são listagem confirmada. Se uma consulta isolada falhar, clique **Tentar novamente só esta RBL** nos detalhes: o sistema consulta apenas aquela lista para aquele IP e registra um novo snapshot com os horários originais das demais listas. O botão só aparece para consultas elegíveis e listas ainda habilitadas.

- Spamhaus ZEN vem desabilitada por padrão. Para usar DQS, configure sua chave no painel RBLs antes de habilitar a lista. `127.255.255.254` indica problema de acesso via resolvedor e não presença na lista.
- APEWS Level 2 começa desabilitada devido a falhas recorrentes de resolução DNS.
- UCEPROTECT Level 3 pode produzir indicadores amplos por ASN; desative-a globalmente ou ignore-a apenas no IP relevante.

## Histórico e alertas

Em cada IP, os episódios de listagem guardam detecção, última confirmação, encerramento, motivo e observação. As observações longas usam quebra de linha; o histórico não é apagado ao silenciar.

- **Encerrar alerta agora:** fecha o episódio atual. Um novo teste ainda listado pode criar um novo episódio.
- **Ignorar esta RBL neste IP:** silencia alertas e e-mails para aquele par IP/RBL, sem falsificar o resultado DNS.
- **Voltar a alertar:** remove a regra de silêncio.
- **Desabilitar uma RBL globalmente:** encerra os alertas operacionais dessa RBL para todos os IPs; histórico permanece.

## Alertas SMTP

Entre em **SMTP e alertas** como administrador. Configure host/IP, porta, STARTTLS ou SSL/TLS, usuário, senha, remetente, destinatários e ativação. Salve e utilize **Enviar e-mail de teste**. Para trocar a senha, preencha uma nova; deixar vazio mantém a anterior. Para remover, use a opção específica.

O sistema cria uma notificação quando abre um incidente novo em RBL habilitada e não ignorada. Não envia uma mensagem idêntica a cada rechecagem do mesmo episódio. E-mails pendentes que se tornarem irrelevantes por desativação ou ignore deixam de ser enviados. Em caso de falha SMTP, o motivo simplificado é registrado, e há nova tentativa nas rotinas de processamento.

**Atenção:** senhas SMTP e chaves de provedores são armazenadas no SQLite local. Restrinja o acesso a `data/`, aos backups e à rede do painel.

## Configuração de monitoramento

Em **Configurações**, ajuste o intervalo em minutos e o timeout DNS. Consultas dependem da conectividade externa, do resolvedor em uso e das regras de cada serviço DNSBL. A opção `check_on_start` em `config.json` controla se há uma varredura ao iniciar o serviço.

## Domínios

A área Domínios oferece dois fluxos independentes: cadastro para monitoramento automático com histórico/alertas e consulta pontual sem cadastro ou gravação do relatório. Veja [DOMINIOS.md](DOMINIOS.md) para configurar listas, interpretar resultados e entender as limitações de SPF, DMARC e DKIM.
