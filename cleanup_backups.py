#!/usr/bin/env python3
"""Keep five updater snapshots. Preview by default; --apply actually removes."""
import argparse
from datetime import datetime
from pathlib import Path
import re
import shutil
import sys

KEEP = 5
NAME = re.compile(r'\d{8}-\d{6}-[0-9a-f]{7,40}')


def prune(app_dir, apply=False, protect=None):
    app_dir = Path(app_dir).resolve(strict=True)
    root = app_dir / 'backups'
    if root.is_symlink():
        raise ValueError('O diretório backups não pode ser um link simbólico.')
    if not root.exists():
        return []
    if not root.is_dir() or root.resolve() != root:
        raise ValueError('Diretório de backups inválido.')
    protected = None
    if protect:
        protected = Path(protect)
        if protected.parent != root or protected.is_symlink() or not protected.is_dir():
            raise ValueError('Backup protegido inválido.')
    candidates = []
    for entry in root.iterdir():
        if not NAME.fullmatch(entry.name) or entry.is_symlink() or not entry.is_dir():
            continue
        try:
            datetime.strptime(entry.name[:15], '%Y%m%d-%H%M%S')
        except ValueError:
            continue
        # Recognize legacy updater snapshots, not arbitrary administrator files.
        archive = entry / 'app-before.tar'
        if not archive.is_file() or archive.is_symlink():
            continue
        if entry.resolve().parent != root or any(item.is_symlink() for item in entry.rglob('*')):
            print('Ignorado por segurança: ' + entry.name, file=sys.stderr)
            continue
        candidates.append(entry)
    candidates.sort(key=lambda item: item.name, reverse=True)
    keep = {protected} if protected in candidates else set()
    for candidate in candidates:
        if len(keep) >= KEEP:
            break
        keep.add(candidate)
    removed = []
    for entry in candidates:
        if entry in keep:
            continue
        # Recheck the exact absolute target immediately before recursive removal.
        if root.is_symlink() or entry.is_symlink() or entry.resolve().parent != root:
            raise ValueError('Destino de limpeza mudou; operação interrompida.')
        if apply:
            shutil.rmtree(entry)
        print(('Removido: ' if apply else 'Seria removido: ') + entry.name)
        removed.append(entry.name)
    return removed


def main():
    parser = argparse.ArgumentParser(description='Mantém os cinco backups mais recentes do atualizador. Sem --apply apenas simula.')
    parser.add_argument('--apply', action='store_true', help='Remove definitivamente os backups excedentes.')
    parser.add_argument('--protect', help='Caminho absoluto do backup usado para rollback; reservado ao atualizador.')
    args = parser.parse_args()
    try:
        removed = prune(Path(__file__).resolve().parent, args.apply, args.protect)
        print(f'Limpeza {"aplicada" if args.apply else "simulada"}: {len(removed)} backup(s) excedente(s). Retenção: {KEEP}.')
        return 0
    except (OSError, ValueError) as exc:
        print('ERRO na limpeza de backups: ' + str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
