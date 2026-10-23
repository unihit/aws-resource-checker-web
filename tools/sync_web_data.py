"""Refresh the synthetic WAR sample and the three-file SHA256 download manifest."""
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT / 'collector'))
import war


def sync():
    page = ROOT / 'index.html'
    text = page.read_text(encoding='utf-8')
    pattern = r'window\.CHECKER_DATA = (\{[^\n]+\});'
    matches = list(re.finditer(pattern,text))
    if len(matches) != 1:
        raise ValueError('Expected one embedded data block')
    match = matches[0]
    data = json.loads(match.group(1))
    data['sample']['war'] = war.evaluate(data['sample'])
    data['sample']['war_enabled'] = True
    data['collector'] = {name:hashlib.sha256((ROOT / 'collector' / name).read_bytes()).hexdigest()
                         for name in ('checker.py','cloudshell.py','war.py')}
    encoded = json.dumps(data,ensure_ascii=False).replace('<','\\u003c')
    text = text[:match.start(1)] + encoded + text[match.end(1):]
    page.write_text(text,encoding='utf-8')


if __name__ == '__main__':
    sync()
