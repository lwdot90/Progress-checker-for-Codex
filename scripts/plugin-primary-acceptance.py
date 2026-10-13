#!/usr/bin/env python3
"""OFF-default adapter for a live externally activated primary pilot.

Import/call integration is explicitly enabled by paired acceptance-runner flags.
No function starts/activates Codex, executes approved project checks, reads auth,
changes config, or signals a producer. Its only external request is read-events.
A fresh zero-cap source-free recipient runs independently under the shared budget.
Uncovered semantics remain nonzero/completeFalse; reports cannot replace a stream.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import time

ROOT = Path(__file__).resolve().parent.parent
TRUST_DISCLOSURE = 'Hidden host producer identity still relies on separately reviewed trusted registration.'
RECONCILIATION_AND_AUDIT = 'Final active-observer run reconciliation and complete semantic audit remain staged.'
RECIPIENT_AND_RECONCILIATION = 'Fresh source-free recipient and exact active-observer reconciliation not yet integrated.'


def observation_scope(observed, *, reconciled, source_free, attestation_sha256,
                      semantic_validated=False):
    """Discharge only exact known predicates; preserve all unknown gates."""
    gates = observed.get('unqualified')
    if not isinstance(gates, list) or any(not isinstance(gate, str) or not gate for gate in gates):
        raise RuntimeError('Observation must declare an explicit list of qualification gates')
    identity = observed.get('identity', {})
    trusted = (identity.get('policy') == 'explicit approved immutable host identity attestation plus kernel peer lifetime'
               and identity.get('hidden_host_identity_independently_verified') is False
               and identity.get('trusted_attestation_sha256') == attestation_sha256)
    missing, discharged, disclosures = [], [], []
    for gate in gates:
        if gate == TRUST_DISCLOSURE and trusted:
            disclosures.append(gate)
        elif gate == RECONCILIATION_AND_AUDIT and reconciled and semantic_validated:
            discharged.append({'gate': gate, 'predicate': 'fresh local raw semantic validation and exact active-observer reconciliation'})
        elif gate == RECIPIENT_AND_RECONCILIATION and reconciled and source_free:
            discharged.append({'gate': gate, 'predicate': 'fresh source-free recipient and exact active-observer reconciliation'})
        else:
            missing.append(gate)
    return missing, {'original_gates': list(gates), 'discharged': discharged,
                     'disclosures': disclosures, 'remaining': list(missing)}


def load(acceptance, name, path):
    path = Path(path)
    source = path.read_bytes()
    acceptance.artifact(name, path)
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(source, str(path), 'exec'), module.__dict__)
    if hashlib.sha256(path.read_bytes()).digest() != hashlib.sha256(source).digest():
        raise RuntimeError('Behavioral module changed during immutable load')
    return module


def managed_workflow_coverage(acceptance, directory, budget, *, semantic_validated):
    """Pair fresh native planning proof with the original managed-block probes."""
    if semantic_validated is not True:
        return ['Managed workflow requires fresh authenticated primary semantic proof.']
    runner = load(acceptance, 'primary-managed-workflow', ROOT/'scripts/plugin-acceptance.py')
    runtime = load(acceptance, 'primary-managed-workflow-runtime', ROOT/'scripts/plugin-acceptance-runtime.py')
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    before = len(acceptance.report['assertions'])
    with budget.operation(30):
        product, code = runtime.run_acceptance(
            Path(acceptance.options.archive), 'agent-workflow', directory/'public-runtime',
            timeout=budget.remaining(30))
        # This exact gate is supplied by the fresh native semantic proof above;
        # the marked empty public fixture proves the original managed probes.
        authenticated_gate = 'Authenticated standard Codex uses the installed skill to derive accepted scope and report actual evidence independently of claims.'
        if (code not in (0, 2) or product.get('status') not in ('passed', 'partial')
                or product.get('unqualified') not in ([], [authenticated_gate])
                or product.get('archive', {}).get('sha256') != acceptance.report['archive']['sha256']
                or product.get('test_runtime', {}).get('test_sources', {}).get('plugin-acceptance.py')
                   != acceptance.report['artifacts']['primary-managed-workflow']['sha256']):
            raise RuntimeError('Current managed workflow runtime did not qualify the exact original probes')
        for assertion in product.get('assertions', []):
            acceptance.check(assertion['name'], assertion.get('passed') is True, assertion.get('detail'))
    assertions = acceptance.report['assertions'][before:]
    if not assertions or any(item.get('passed') is not True for item in assertions):
        raise RuntimeError('Managed workflow probes did not pass')
    acceptance.report['managed_workflow'] = {
        'fresh_authenticated_semantics': True,
        'assertion_count': len(assertions),
        'test_runtime': product['test_runtime'],
        'coverage': 'Original managed setup/removal, accepted scope, claims and refusal probes plus fresh native primary planning.'}
    return []


def standard_codex_pilot_attested(acceptance, directory, attestation_path,
                                 attestation_sha256, readiness_path):
    """Return missing predicates; caller must fail while this list is nonempty."""
    if acceptance.options.milestone != 'standard-codex-pilot':
        raise RuntimeError('Live attestation is only accepted for standard-codex-pilot')
    report = acceptance.report['attested_primary_pilot'] = {
        'complete': False, 'status': 'staged', 'approval_created': False,
        'workflow_started_or_activated': False, 'credential_or_home_access': False,
        'coverage': 'Fresh live raw primary semantics, current observer reconciliation and fresh zero-cap source-free recipient.'}
    missing = []
    if not all([attestation_path, attestation_sha256, readiness_path]):
        return ['Exact immutable attestation path/SHA and mutable readiness path must be paired.']
    if not getattr(acceptance.options, 'archive', None) or not getattr(acceptance.options, 'recipient_old_archive', None):
        return ['Exact current and pinned prior recipient archives are required.']
    observer = load(acceptance, 'primary-observer', ROOT/'scripts/plugin-primary-observer.py')
    release = load(acceptance, 'primary-release-budget', ROOT/'scripts/plugin-release-acceptance.py')
    budget = release.Deadline(started_at=acceptance.started_at, work_seconds=210, total_seconds=295)
    acceptance.artifact('immutable-primary-attestation', Path(attestation_path))
    acceptance.artifact('fresh-primary-current-archive', Path(acceptance.options.archive))
    acceptance.artifact('fresh-primary-prior-archive', Path(acceptance.options.recipient_old_archive))
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    # Read only public root configuration; host home/private backend records remain inaccessible.
    config_path = ROOT/'.progress-checker/config.json'
    with budget.operation(30):
        config = json.loads(config_path.read_bytes())
        definitions = [c for c in config['checks'] if c['id'] == 'standard-codex-pilot']
        if len(definitions) != 1:
            raise RuntimeError('Exactly one configured standard-codex-pilot definition required')
        definition = definitions[0]
        argv = definition['argv']
        # The final binding must contain the exact immutable digest and both paths.
        bindings = {'--primary-attestation': str(attestation_path),
                    '--primary-attestation-sha256': attestation_sha256,
                    '--primary-readiness': str(readiness_path)}
        job = getattr(acceptance.options, 'live_job', None)
        if job is not None:
            job.definition(definition)
            if job.value['attestation_path'] != str(attestation_path) or job.value['sha256'] != attestation_sha256 or job.value['readiness_path'] != str(readiness_path):
                raise RuntimeError('Stable selection differs from actual primary observation')
        else:
            for flag, value in bindings.items():
                positions = [i for i, token in enumerate(argv) if token == flag]
                if len(positions) != 1 or positions[0]+1 >= len(argv) or argv[positions[0]+1] != value:
                    raise RuntimeError('Approved observer argv lacks exact paired binding: ' + flag)
        report['observer_definition'] = definition
        observed = observer.consume_attested(attestation_path, attestation_sha256, readiness_path,
                                            deadline=time.monotonic()+budget.remaining(90))
        context = observed.pop('_live_validation_context', None)
        if context is None or not context['fresh_projects']:
            raise RuntimeError('Fresh live raw project reconciliation context missing')
        readiness, _ = observer.owned_json(readiness_path)
        if readiness.get('archive_sha256') != acceptance.report.get('archive', {}).get('sha256'):
            raise RuntimeError('Live primary archive pin differs from actual acceptance archive')
        if context['verified']['config'] != config:
            raise RuntimeError('Live accepted config differs from readonly root definition')
        reconciliations = [observer.reconcile_current_project(
            project, context['verified'], readiness, definition,
            expected_observer_run_id=observed.get('expected_observer_run_id'))
            for project in context['fresh_projects']]
        observed['observer_reconciliation'] = reconciliations
        report['observation'] = observed
    # Preserve full scope: a normal arithmetic answer while the checker is available
    # does not prove ordinary Codex behavior when that checker is unavailable.
    unavailable = context.get('unavailable_proof', {})
    report['unavailable_proof'] = unavailable
    if not all(unavailable.get(key) is True for key in ['failed_startup_observed', 'installed_skill_enabled', 'ordinary_turn_completed']):
        missing.append('Fresh native ordinary-prompt behavior while the checker is unavailable is not present in the registered workflow.')
    acceptance.artifact('fresh-recipient-helper', ROOT/'scripts/plugin-sandbox-recipient.py')
    acceptance.artifact('fresh-recipient-harness', ROOT/'scripts/plugin-recipient-qualify.py')
    recipient = release.nested_qualification(
        Path(acceptance.options.archive), directory/'fresh-recipient',
        'Explicit source-free zero-cap attested-pilot qualification', budget,
        old_archive=Path(acceptance.options.recipient_old_archive))
    report['fresh_recipient'] = recipient
    native = recipient.get('recipient', {})
    inventory = recipient.get('nested_inventory', {})
    capabilities = native.get('recipient_capabilities', {})
    archive_hash = acceptance.report.get('archive', {}).get('sha256')
    source_free = (
        native.get('status') == 'passed'
        and recipient.get('archive_sha256') == archive_hash
        and native.get('upgrade_archive_sha256') == archive_hash
        and inventory.get('worktree_visible') is False
        and inventory.get('host_home_visible') is False
        and set(capabilities) == {'CapEff', 'CapPrm', 'CapBnd'}
        and all(int(value, 16) == 0 for value in capabilities.values())
        and 'no Rust Cargo Node' in native.get('assertions', []))
    if not source_free:
        missing.append('Fresh exact source-free zero-cap recipient dependency qualification did not pass.')
    report['recipient_dependency_predicate'] = source_free
    observation_missing, classification = observation_scope(
        observed, reconciled=bool(reconciliations), source_free=source_free,
        attestation_sha256=attestation_sha256,
        semantic_validated=context.get('semantic_validation_passed') is True)
    report['observation_scope'] = classification
    missing.extend(observation_missing)
    # Only the fresh local observer creates this context after validating raw frames.
    # Producer metadata/report fields are never used to assign this predicate.
    if context.get('semantic_validation_passed') is not True:
        missing.append('Fresh local raw semantic validation did not pass.')
    missing.extend(managed_workflow_coverage(
        acceptance, directory/'managed-workflow', budget,
        semantic_validated=context.get('semantic_validation_passed')))
    report.update(status='partial' if missing else 'passed', complete=not missing, unqualified=missing,
                  elapsed_seconds=time.monotonic()-acceptance.started_at)
    return missing
