# Atualização por Git — sem reinstalação

O GitHub é a fonte para obter a versão mais atual do RBL Monitor. O `update.sh` busca o código de [lucianopm/rbl-monitor](https://github.com/lucianopm/rbl-monitor), preservando os dados e configurações locais. O repositório público pode ser consultado sem conta ou token.

## 1. Atualizar servidor já instalado

Os exemplos usam `/opt/rbl-monitor`. Em uma instalação personalizada, substitua esse caminho pelo diretório onde o pacote foi descompactado e instalado. `update.sh` detecta sua própria pasta, exige banco em `data/monitor.db` dentro dela e preserva as configurações locais. O script de agendamento também gera sua unidade com esse caminho. Não mova uma instalação ativa: o serviço e o ambiente Python têm caminhos absolutos.

Esta atualização invalida sessões de versões anteriores; faça login novamente após aplicar. Mudanças de senha, perfil e estado dos usuários também revogam suas sessões antigas.

O repositório oficial e a branch `main` são usados por padrão, inclusive na primeira execução:

```bash
sudo bash /opt/rbl-monitor/update.sh
```

Para informar explicitamente a origem ou substituir uma configuração anterior:

```bash
sudo bash /opt/rbl-monitor/update.sh \
  --repo https://github.com/lucianopm/rbl-monitor.git \
  --branch main
```

O endereço e a branch serão gravados em `/opt/rbl-monitor/.git-update.conf` após uma atualização bem-sucedida. Nas próximas vezes:

```bash
sudo bash /opt/rbl-monitor/update.sh
```

Em automações sem terminal interativo, use `--yes` **somente se confiar no repositório**:

```bash
sudo bash /opt/rbl-monitor/update.sh --yes
```

O pacote inclui agendamento opcional. Depois de concluir uma atualização manual com sucesso, habilite:

```bash
sudo bash /opt/rbl-monitor/enable-auto-update.sh
sudo systemctl list-timers rbl-monitor-update.timer
sudo journalctl -u rbl-monitor-update.service -n 100 --no-pager
```

O timer roda diariamente às 04h no fuso do servidor, com atraso aleatório de até 15 minutos. O serviço usa root e instala a branch configurada: restrinja quem pode publicar nela. Para desabilitar: `sudo bash /opt/rbl-monitor/enable-auto-update.sh --disable`. O timer não é ativado pelo instalador. Faça backup externo e teste em homologação antes de habilitar.

## Selecionar ou trocar o canal

```bash
# Produção / estável
sudo bash /opt/rbl-monitor/update.sh --main
# Homologação / desenvolvimento
sudo bash /opt/rbl-monitor/update.sh --dev
```

Também aceita `--branch main` ou `--branch dev`. O canal escolhido é gravado em `.git-update.conf` após sucesso. Sem argumento, a atualização usa o canal salvo ou main na primeira execução. O timer automático segue essa configuração: ao trocar para dev, suas próximas execuções também usarão dev. Cada troca usa os mesmos backups, verificação e tentativa de rollback.

`dev` pode receber mudanças ainda não homologadas. Retornar a main troca o código e dependências, mas não desfaz automaticamente migrações já concluídas em dev; confira compatibilidade e use um backup conhecido se necessário. Use dev preferencialmente em uma instalação de teste separada. Personalizações em `config.json` e `rbls.json` continuam preservadas em ambos os canais. Portanto, a alteração do padrão da Spamhaus ZEN não desativa a lista automaticamente em instalações antigas: faça isso pelo painel.

## 2. O que o script faz

1. Obtém a branch configurada em um diretório temporário usando `git clone`.
2. Confere arquivos obrigatórios, sintaxe Python/JSON/Bash e rejeita links simbólicos e arquivos sensíveis versionados.
3. Monta uma nova `.venv.next` e instala as dependências sem interromper o serviço.
4. Gera backup consistente do SQLite via API de backup do `sqlite3`, copia `.env` e os JSON locais e arquiva o código anterior em `backups/`.
5. Para o serviço, substitui os arquivos versionados do projeto (exceto configurações locais), troca a `.venv`, inicia e valida `/health`.
6. Se ocorrer falha após a parada, tenta restaurar código, dependências, unidade systemd e o banco capturado com o serviço parado, incluindo alterações de esquema. Escritas realizadas durante a tentativa de atualização são descartadas nesse rollback. O script verifica o endpoint após a reversão, mas exige conferência manual se o serviço não recuperar.
7. Em caso de sucesso, grava `.git-version`, registra a origem e mantém o backup.

As mudanças feitas pelo painel ficam no SQLite e são preservadas. `config.json` e `rbls.json` locais também são preservados para evitar perder personalizações. Se o repositório trouxer alterações nesses dois arquivos, revise e aplique-as manualmente quando necessário.

## 3. Comandos de conferência

```bash
sudo systemctl status rbl-monitor --no-pager
sudo journalctl -u rbl-monitor -n 80 --no-pager
curl -fsS http://127.0.0.1:8080/health
sudo cat /opt/rbl-monitor/.git-version
```

Os backups são mantidos em `/opt/rbl-monitor/backups/`. **Mantenha cópias externas**: um backup no mesmo disco não protege de falha física nem ransomware.

### Restauração manual do banco (se necessária)

Pare o serviço, faça uma cópia dos arquivos atuais e só então restaure um backup conhecido:

```bash
sudo systemctl stop rbl-monitor
sudo tar -C /opt/rbl-monitor -czf /tmp/rbl-monitor-data-antes-de-restaurar.tgz data/
sudo rm -f /opt/rbl-monitor/data/monitor.db-wal /opt/rbl-monitor/data/monitor.db-shm
sudo cp -a /opt/rbl-monitor/backups/NOME_DO_BACKUP/monitor.db /opt/rbl-monitor/data/monitor.db
sudo chown rblmonitor:rblmonitor /opt/rbl-monitor/data/monitor.db
sudo systemctl start rbl-monitor
```

**Importante:** o exemplo remove os arquivos SQLite `-wal`/`-shm` somente depois de parar o serviço e salvar uma cópia de `data/`. Confirme a compatibilidade do backup com a versão do código. Não restaure um banco antigo indiscriminadamente. Consulte os logs se houver erro e faça o procedimento em janela de manutenção.
