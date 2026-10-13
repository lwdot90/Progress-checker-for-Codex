#!/usr/bin/env python3
"""Check policy/architecture artifacts without asserting platform qualification."""
import json
from pathlib import Path

root=Path(__file__).resolve().parent.parent
policy=(root/'docs/COMMANDS_AND_LOGS.md').read_text()
for term in ('root-owned','/usr','venv','nvm','pyenv','HOME=/tmp','Networking is disabled','does **not** automatically discover','OS process listing','0.5.0-dev'):
    assert term in policy, 'Missing command/privacy limitation: '+term
architecture=(root/'docs/SERVICE_ARCHITECTURE.md').read_text()
for term in ('same OS user','separate OS privilege boundary','unrestricted host process','one writer','cold startup'):
    assert term in architecture, 'Missing architecture limitation: '+term
receipt=json.loads((root/'docs/receipts/service-resources.json').read_text())
assert receipt['observed_at'] and receipt['installed_plugin_version']=='0.4.0-dev'
assert receipt['summed_rss_kib']==sum(p['rss_kib'] for p in receipt['processes'])
assert all(p['role'] in ('checker-global','checker-plugin','progress-checker','progress-checker-mcp') for p in receipt['processes'])
assert receipt['summed_rss_kib']>0
print('PASS: explicit command/log limitations and dated architecture resource observation')
