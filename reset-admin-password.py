#!/usr/bin/env python3
"""Local administrative recovery; never accepts passwords on command line."""
import getpass
import os
import sqlite3
import secrets
from datetime import datetime, timezone
from pathlib import Path
from werkzeug.security import generate_password_hash


def reset_password(database, username, password):
    if len(password) < 10:
        raise ValueError('A senha deve ter pelo menos 10 caracteres.')
    connection = sqlite3.connect(Path(database).resolve().as_uri() + '?mode=rw', uri=True, timeout=30)
    try:
        with connection:
            account = connection.execute(
                'SELECT id FROM users WHERE username=? AND is_admin=1', (username,)).fetchone()
            if not account:
                raise ValueError('Conta administrativa não encontrada. Nada foi alterado.')
            connection.execute('UPDATE users SET password_hash=?,active=1,session_token=? WHERE id=?',
                               (generate_password_hash(password), secrets.token_hex(32), account[0]))
            connection.execute('DELETE FROM login_attempts WHERE username=?', (username,))
    finally:
        connection.close()


def main():
    if hasattr(os, 'geteuid') and os.geteuid() != 0:
        raise SystemExit('Execute com sudo.')
    base = Path(__file__).resolve().parent
    database = base / 'data/monitor.db'
    backups = base / 'backups'
    if database.is_symlink() or backups.is_symlink() or (base / 'data').is_symlink():
        raise SystemExit('Dados/backups não podem usar symlinks.')
    if not database.is_file():
        raise SystemExit('Banco local não encontrado. Nada foi alterado.')
    password = getpass.getpass('Nova senha de admin (mínimo 10 caracteres): ')
    if password != getpass.getpass('Confirme a nova senha: '):
        raise SystemExit('Confirmação diferente. Nada foi alterado.')
    if len(password) < 10:
        raise SystemExit('Senha muito curta. Nada foi alterado.')
    os.umask(0o077)
    backups.mkdir(mode=0o700, exist_ok=True)
    backups.chmod(0o700)
    backup = backups / ('password-reset-' + datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f') + '.db')
    source = sqlite3.connect(database.resolve().as_uri() + '?mode=ro', uri=True)
    target = sqlite3.connect(backup)
    try:
        source.backup(target)
    finally:
        target.close()
        source.close()
    reset_password(database, 'admin', password)
    print('Senha de admin redefinida; conta ativada e bloqueio de tentativas removido.')
    print('IPs, histórico e configurações preservados. Não é necessário reiniciar o serviço.')
    print('Backup:', backup)


if __name__ == '__main__':
    main()
