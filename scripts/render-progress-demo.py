#!/usr/bin/env python3
"""Render a dated public MCP summary, not a desktop recording or check execution."""
import hashlib
import json
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

root = Path(__file__).resolve().parent.parent
receipt_path = root / 'docs/receipts/progress-demo.json'
receipt = json.loads(receipt_path.read_text())
counts = receipt['counts']
font_path = Path('/usr/share/fonts/dejavu-sans-mono-fonts/DejaVuSansMono.ttf')
if not font_path.exists():
    font_path = Path('/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf')
font = ImageFont.truetype(str(font_path), 23) if font_path.exists() else ImageFont.load_default(size=23)
small = ImageFont.truetype(str(font_path), 16) if font_path.exists() else ImageFont.load_default(size=16)
lines = [
    ('USER', 'Track this project.'),
    ('CHECKER', 'Project connected. Existing plan preserved.'),
    ('USER', "What’s the progress?"),
    ('CHECKER', f"{counts['implemented']} implemented  |  {counts['planned']} planned"),
    ('CHECKER', f"{counts['verified']} of {counts['scoped']} verified"),
    ('CHECKER', 'Earlier passing evidence is stale.'),
    ('CHECKER', 'No project checks were run in this demo.'),
]
frames = []
for visible in range(1, len(lines) + 1):
    frame = Image.new('RGB', (1050, 620), '#111827')
    draw = ImageDraw.Draw(frame)
    draw.text((38, 28), 'Progress Checker for Codex', font=font, fill='#f9fafb')
    draw.text((38, 65), 'Actual tool result rendered as a conversation', font=small, fill='#9ca3af')
    for i, (role, message) in enumerate(lines[:visible]):
        y = 120 + i * 58
        draw.text((38, y), role, font=small, fill='#60a5fa' if role == 'USER' else '#34d399')
        draw.text((155, y - 4), message, font=font, fill='#e5e7eb')
    draw.text((38, 580), 'Recorded ' + receipt['observed_at'][:10] + ' | v0.4.0-dev | approval/check demo pending', font=small, fill='#9ca3af')
    frames.append(frame)
target = root / 'docs/assets/progress-demo.gif'
frames[0].save(target, save_all=True, append_images=frames[1:], duration=[1100] * 6 + [5000], loop=0)
receipt['gif_sha256'] = hashlib.sha256(target.read_bytes()).hexdigest()
receipt_path.write_text(json.dumps(receipt, indent=2) + '\n')
print('Rendered dated tool result:', target)
