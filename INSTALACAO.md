# Instalação do zero — Ubuntu / Debian

`install.sh` instala do zero e cancela se detectar uma versão anterior, preservando seus dados. Use `update.sh` para atualizar. Uma reinstalação exige backup e remoção manual dos caminhos antigos previamente conferidos.

## 1. Pré-requisitos

- Ubuntu Server ou Debian com `systemd` ativo (não é um instalador para Windows ou containers sem systemd).
- `sudo` e acesso à Internet (repositórios APT + PyPI) durante a instalação.
- Resolução DNS funcional para consultar zonas de RBL e registros PTR/A/AAAA.
- Porta TCP 8080 disponível; ajuste com `--port 8090` se necessário.
- Firewall liberando a porta apenas para sua rede interna/VPN; evitar exposição pública.

## 2. Baixar e extrair o ZIP

Baixe o arquivo `rbl-monitor-consolidado.zip` anexado ao [release mais recente](https://github.com/lucianopm/rbl-monitor/releases/latest). Use esse pacote, que contém a pasta `rbl-monitor/`. No servidor, em um diretório de trabalho, rode:

```bash
sudo apt-get update
sudo apt-get install -y unzip curl
curl -fL https://github.com/lucianopm/rbl-monitor/releases/latest/download/rbl-monitor-consolidado.zip -o rbl-monitor-consolidado.zip
unzip rbl-monitor-consolidado.zip
cd rbl-monitor
```

## 3. Executar o instalador

```bash
sudo bash install.sh
```

Para porta alternativa:

```bash
sudo bash install.sh --port 8090
```

O script executa automaticamente:

1. Verificação do sistema, arquivos e sintaxe.
2. Instalação do Python, venv, pip, OpenSSL e ferramentas necessárias.
3. Cancelamento sem apagar dados ao encontrar instalação anterior.
4. Criação do usuário de serviço `rblmonitor` e da pasta `/opt/rbl-monitor`.
5. Instalação de bibliotecas Python em `/opt/rbl-monitor/.venv`.
6. Geração local de uma chave aleatória de sessão e senha inicial do administrador.
7. Criação do SQLite em `/opt/rbl-monitor/data/monitor.db` e cadastro inicial de `admin`.
8. Registro de `/opt/rbl-monitor/rbl-monitor.service` no systemd, inicialização e teste de `/health`.
9. Remoção da senha inicial em texto claro do `.env` após o primeiro cadastro.

Anote a senha que aparece no terminal ao final. Se perder essa senha, o instalador não permite recuperá-la; uma recuperação administrativa deve alterar somente o hash da conta após backup e com o serviço parado.

O argumento `--yes` é aceito por compatibilidade e não permite sobrescrever instalações existentes.

## 4. Acessar e configurar

- Abra `http://IP_DO_SERVIDOR:8080/login` (ou a porta definida na instalação).
- Login inicial: `admin` / senha exibida pelo instalador.
- Em **Minha conta**, substitua a senha inicial.
- Em **Configurações**, defina o intervalo de varredura e timeout DNS.
- Em **RBLs**, ajuste as listas e informe credenciais de provedores, se necessário.
- Em **SMTP e alertas**, informe o servidor e faça um envio de teste.
- Cadastre os IPs a monitorar.

## 5. Arquivos e permissões

```text
/opt/rbl-monitor/
  app.py, extensions.py, wsgi.py
  install.sh, update.sh, README.md, *.md
  config.json, rbls.json
  templates/, static/
  .env                    # segredo local — root, 0600
  .venv/                 # ambiente Python
  data/monitor.db        # SQLite — usuário rblmonitor
  backups/               # gerado ao atualizar via Git
  rbl-monitor.service    # unidade systemd gerada
```

Não copie `.env`, `data/` nem `backups/` para GitHub. Não modifique diretamente dados no SQLite enquanto o serviço estiver rodando.

Código, templates, scripts e ambiente Python pertencem a `root:rblmonitor` (leitura/execução pelo serviço, sem permissão de alterar código). `data/` pertence a `rblmonitor:rblmonitor`, com modo 0700. `.env` permanece `root:root`, modo 0600: o systemd lê esse arquivo antes de iniciar o processo como `rblmonitor`. Backups também são restritos ao root. Não execute `chown -R rblmonitor:rblmonitor /opt/rbl-monitor`, pois permitiria ao serviço alterar scripts que o atualizador executa como root.

## Recuperar acesso administrativo

A senha não pode ser recuperada em texto claro: o banco guarda apenas o hash. Para definir uma nova senha na instalação atualizada:

```bash
sudo /opt/rbl-monitor/.venv/bin/python /opt/rbl-monitor/reset-admin-password.py
```

Digite e confirme uma senha de pelo menos 10 caracteres; a entrada fica oculta. O script cria backup SQLite em `backups/`, redefine somente a conta `admin`, reativa essa conta e limpa seu bloqueio de tentativas. IPs, histórico e configurações são preservados. Não exige reiniciar o serviço. Não informe a senha em argumentos nem coloque-a no `.env`. O script exige acesso sudo no servidor. Se o arquivo não existir, atualize a aplicação antes.

## Testar e diagnosticar

```bash
sudo systemctl status rbl-monitor --no-pager
sudo journalctl -u rbl-monitor -n 80 --no-pager
curl -fsS http://127.0.0.1:8080/health
```

De outra estação, acesse `http://IP_DO_SERVIDOR:8080`. Se funcionar no servidor mas não na estação, confira firewall, roteamento e a porta escolhida. Se o serviço não iniciar, verifique `journalctl` e permissões em `data/`.

Para gerar manualmente uma chave aleatória **sem site externo**:

```bash
openssl rand -hex 32
```

O instalador já faz isso automaticamente. Não compartilhe o resultado nem coloque-o em arquivos versionados.

**Nota:** o Gunicorn usa HTTP puro; adequado somente para uma rede interna realmente confiável. Se o ambiente incluir redes compartilhadas/não confiáveis, coloque HTTPS em um proxy reverso ou VPN.
