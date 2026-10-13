#!/usr/bin/env python3
"""Validate user artifacts and dated public observations; never run project checks.

These checks do not establish continuous remote state or an approval workflow.
The existing live-service-approval check retains that behavioral coverage.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / 'docs'


def require(ok, message):
    if not ok:
        raise SystemExit(message)


def read_receipt(name):
    path = DOCS / 'receipts' / name
    require(path.is_file() and not path.is_symlink(), 'Missing regular public receipt: ' + name)
    return json.loads(path.read_text())


def local_links(path):
    for target in re.findall(r'\]\(([^)]+)\)', path.read_text()):
        if '://' in target or target.startswith('#'):
            continue
        require((path.parent / target.split('#')[0]).exists(), 'Missing link: ' + target)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', required=True, choices=[
        'user-quickstart-demo', 'repository-discovery', 'ubuntu-portability-assessment',
        'user-doc-navigation', 'independent-user-trial'])
    case = parser.parse_args().case
    guide = DOCS / 'USER_GUIDE.md'
    if case == 'user-quickstart-demo':
        text = guide.read_text()
        for phrase in ('Track this project', "What’s the progress?", 'CI', 'unchanged check', 'recorded tool result'):
            require(phrase in text, 'Quickstart misses ' + phrase)
        receipt = read_receipt('progress-demo.json')
        require(receipt['tool'] == 'checker_get_progress' and receipt['plugin_version'] == '0.4.0-dev', 'Unexpected demo source')
        counts = receipt['counts']
        require(counts['implemented'] + counts['planned'] == counts['scoped'], 'Demo counts differ')
        require(0 <= counts['verified'] <= counts['scoped'], 'Invalid verification count')
        require(receipt['checks_executed'] is False and receipt['rendering'] == 'dated MCP result rendered as conversation; not a screen recording', 'Demo overstates coverage')
        gif = DOCS / 'assets/progress-demo.gif'
        require(gif.read_bytes().startswith((b'GIF87a', b'GIF89a')), 'Invalid GIF')
        require(hashlib.sha256(gif.read_bytes()).hexdigest() == receipt['gif_sha256'], 'Demo asset changed')
        local_links(guide)
    elif case == 'repository-discovery':
        receipt = read_receipt('repository-metadata.json')
        require(receipt['full_name'] == 'lwdot90/Progress-checker-for-Codex', 'Wrong repository')
        require(receipt['description'] == 'A Codex plugin that ties project milestones to fresh passing checks, so agent completion claims come with evidence.', 'Unexpected repository description')
        require({'codex', 'codex-plugin', 'mcp', 'developer-tools', 'verification', 'ai-agents'} <= set(receipt['topics']), 'Missing topics')
        require(receipt['observed_at'] and receipt['observation_source'] == 'GitHub public repository API', 'Missing dated public observation')
    elif case == 'ubuntu-portability-assessment':
        report = DOCS / 'PORTABILITY.md'
        text = report.read_text()
        for phrase in ('dpkg-query', '/var/lib/dpkg', 'fail closed', 'bubblewrap', 'glibc', 'macOS', 'not yet supported'):
            require(phrase in text, 'Portability report misses ' + phrase)
        receipt = read_receipt('portability-source.json')
        require(receipt['scope'] == 'source inspection; no Ubuntu execution or support claim', 'Incorrect portability coverage')
        for name, digest in receipt['sources'].items():
            require(hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest, 'Portability source changed: ' + name)
    elif case == 'user-doc-navigation':
        for path in (ROOT / 'README.md', guide, DOCS / 'release-status.md'):
            local_links(path)
        text = guide.read_text()
        for phrase in ('Install', 'Approve', 'Update', 'Remove', 'Support'):
            require(phrase in text, 'Missing user step: ' + phrase)
        require('development-history.md' in (ROOT / 'README.md').read_text(), 'Development history is not linked')
        require((DOCS / 'development-history.md').is_file(), 'Development material was removed')
    else:
        receipt = read_receipt('independent-user-trial.json')
        require(receipt['participant_kind'] == 'consenting unfamiliar user', 'Developer/agent trial is insufficient')
        require(receipt['platform'] and receipt['version'] and receipt['feedback'], 'Missing user observations')
        require(all(receipt['observed_steps'].get(step) is True for step in
                    ('install', 'track', 'human_approval', 'passing_check')), 'Incomplete user workflow')
        require(receipt['public_run_id'] and receipt['observed_at'], 'Missing actual run observation')
    print('PASS:', case, '(artifact and stated observation coverage only)')


if __name__ == '__main__':
    main()
