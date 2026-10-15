"""Public build information, without reading credentials or invoking Git."""
import re
from pathlib import Path


def build_label(directory=None):
    directory = Path(directory) if directory is not None else Path(__file__).resolve().parent

    def read(name, pattern):
        try:
            with (directory / name).open(encoding='utf-8') as handle:
                value = handle.read(128).strip()
            return value if re.fullmatch(pattern, value) else ''
        except (OSError, UnicodeError):
            return ''

    version = read('VERSION', r'\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?')
    commit = read('.git-version', r'[0-9a-f]{7,40}')
    channel = read('.git-channel', r'main|dev')
    parts = ['v' + version if version else 'versão não informada']
    if channel:
        parts.append(channel)
    if commit:
        parts.append(commit[:12])
    return ' · '.join(parts)
