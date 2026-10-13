#!/usr/bin/env python3
"""Generate reviewable source patches against the verified upstream reference."""

import argparse
import difflib
from pathlib import Path
import runpy
import sys

ROOT = Path(__file__).resolve().parent.parent
BASE = ROOT / "upstream-base"
OVERLAY = ROOT / "prototype-overlay"
OUTPUT = ROOT / "patches"
RELEASE_SNAPSHOT_PATHS = {
    'codex-rs/tui/src/status/snapshots/codex_tui__status__tests__status_snapshot_local_background_server.snap',
    "codex-rs/tui/src/app/snapshots/codex_tui__app__daemon_menu__tests__daemon_cli_confirmation.snap",
    "codex-rs/tui/src/app/snapshots/codex_tui__app__owned_transcript__empty_state_animation_tests__fresh_thread_header.snap",
    "codex-rs/tui/src/app/snapshots/codex_tui__app__tests__app_server_thread_replacement_clears_previous_transcript_before_replay-2.snap",
    "codex-rs/tui/src/app/tests/snapshots/codex_tui__app__tests__realtime_requests__voice_buffered_replay_reconciles_captions.snap",
    "codex-rs/tui/src/app/tests/snapshots/codex_tui__app__tests__realtime_requests__voice_completed_after_thread_switch.snap",
    "codex-rs/tui/src/app/tests/snapshots/codex_tui__app__tests__realtime_requests__voice_replay_reconciles_matching_captions.snap",
    "codex-rs/tui/src/app/tests/snapshots/codex_tui__app__tests__startup_frame_tests__startup_tip_in_transcript.snap",
    "codex-rs/tui/src/app/tests/snapshots/codex_tui__app__tests__realtime_requests__voice_partial_completed_after_thread_switch.snap",
    'codex-rs/tui/src/history_cell/snapshots/codex_tui__history_cell__tests__session_info_availability_nux_tooltip_snapshot.snap',
    'codex-rs/tui/src/snapshots/codex_tui__update_prompt__tests__update_prompt_modal.snap',
    'codex-rs/tui/src/status/snapshots/codex_tui__status__tests__status_server_auth_not_required.snap',
    'codex-rs/tui/src/status/snapshots/codex_tui__status__tests__status_snapshot_cached_limits_hide_credits_without_flag.snap',
    'codex-rs/tui/src/status/snapshots/codex_tui__status__tests__status_snapshot_includes_credits_and_limits.snap',
    'codex-rs/tui/src/status/snapshots/codex_tui__status__tests__status_snapshot_includes_enterprise_monthly_credit_limit.snap',
    'codex-rs/tui/src/status/snapshots/codex_tui__status__tests__status_snapshot_includes_forked_from.snap',
    'codex-rs/tui/src/status/snapshots/codex_tui__status__tests__status_snapshot_includes_monthly_limit.snap',
    'codex-rs/tui/src/status/snapshots/codex_tui__status__tests__status_snapshot_includes_reasoning_details.snap',
    'codex-rs/tui/src/status/snapshots/codex_tui__status__tests__status_snapshot_shows_active_user_defined_profile.snap',
    'codex-rs/tui/src/status/snapshots/codex_tui__status__tests__status_snapshot_shows_auto_review_permissions.snap',
    'codex-rs/tui/src/status/snapshots/codex_tui__status__tests__status_snapshot_shows_chatgpt_plan_without_email.snap',
    'codex-rs/tui/src/status/snapshots/codex_tui__status__tests__status_snapshot_shows_missing_limits_message.snap',
    'codex-rs/tui/src/status/snapshots/codex_tui__status__tests__status_snapshot_shows_refreshing_limits_notice.snap',
    'codex-rs/tui/src/status/snapshots/codex_tui__status__tests__status_snapshot_shows_stale_limits_message.snap',
    'codex-rs/tui/src/status/snapshots/codex_tui__status__tests__status_snapshot_shows_unavailable_limits_message.snap',
    'codex-rs/tui/src/status/snapshots/codex_tui__status__tests__status_snapshot_treats_refreshing_empty_limits_as_unavailable.snap',
    'codex-rs/tui/src/status/snapshots/codex_tui__status__tests__status_snapshot_truncates_halfwidth_kana_in_narrow_terminal.snap',
    'codex-rs/tui/src/status/snapshots/codex_tui__status__tests__status_snapshot_truncates_in_narrow_terminal.snap',
    'codex-rs/tui/src/status/snapshots/codex_tui__status__tests__status_snapshot_uses_default_reasoning_when_config_empty.snap',
    'codex-rs/tui/src/status/snapshots/codex_tui__status__tests__status_snapshot_uses_generic_limit_labels_for_unsupported_windows.snap',
    'codex-rs/tui/src/status/snapshots/codex_tui__status__tests__transcript_overlay_status_rate_limit_refresh.snap',
    'codex-rs/tui/src/status/snapshots/codex_tui__status__tests__status_server_auth_required.snap',
    'codex-rs/tui/src/status/snapshots/codex_tui__status__tests__status_snapshot_remote_server.snap',
    'codex-rs/tui/src/status/snapshots/codex_tui__status__tests__status_snapshot_wraps_enterprise_monthly_credit_details_in_narrow_terminal.snap',
}
RELEASE_BARE_VERSION_SNAPSHOT_PATHS = {
    'codex-rs/tui/src/snapshots/codex_tui__update_prompt__tests__update_prompt_modal.snap',
}
# The inherited stable version 0.160.0 is older than the mock server's 2.0.0.
# Upstream notice policy suppresses these mismatch notices; local 0.0.0 always warned.
RELEASE_EXACT_SNAPSHOTS = {
    "codex-rs/tui/src/app/tests/snapshots/codex_tui__app__tests__active_reconnect__unavailable_conversation.snap": (
        (
            "⚠ A background Codex service is running v2.0.0, different from your Codex CLI\n"
            "  v0.0.0.\n"
        ).encode("utf-8"),
        b"",
    ),
    "codex-rs/tui/src/app/tests/snapshots/codex_tui__app__tests__navigation_reconnect__daemon_command_center_vanished_rename.snap": (
        "  Service v2.0.0 ≠ Codex CLI v0.0.0 · /daemon\n".encode("utf-8"),
        "  ? help  esc back  ↑/↓ move  enter open  n new\n".encode("utf-8"),
    ),
    # These exact layout deltas follow the longer release version in upstream renderers.
    'codex-rs/tui/src/history_cell/snapshots/codex_tui__history_cell__tests__pnpm_update_available_history_cell_snapshot.snap': (
        '│ ✨\u200aUpdate available! 0.0.0 -> 9.9.9             │\n'.encode("utf-8"),
        '│ ✨\u200aUpdate available! 0.160.0 -> 9.9.9           │\n'.encode("utf-8"),
    ),
    'codex-rs/tui/src/history_cell/snapshots/codex_tui__history_cell__tests__standalone_unix_update_available_history_cell_snapshot.snap': (
        '│ ✨\u200aUpdate available! 0.0.0 -> 9.9.9                                                                 │\n'.encode("utf-8"),
        '│ ✨\u200aUpdate available! 0.160.0 -> 9.9.9                                                               │\n'.encode("utf-8"),
    ),
    'codex-rs/tui/src/history_cell/snapshots/codex_tui__history_cell__tests__standalone_windows_update_available_history_cell_snapshot.snap': (
        '│ ✨\u200aUpdate available! 0.0.0 -> 9.9.9                                                                        │\n'.encode("utf-8"),
        '│ ✨\u200aUpdate available! 0.160.0 -> 9.9.9                                                                      │\n'.encode("utf-8"),
    ),
    'codex-rs/tui/src/history_cell/snapshots/codex_tui__history_cell__tests__vite_plus_update_available_history_cell_snapshot.snap': (
        '│ ✨\u200aUpdate available! 0.0.0 -> 9.9.9             │\n'.encode("utf-8"),
        '│ ✨\u200aUpdate available! 0.160.0 -> 9.9.9           │\n'.encode("utf-8"),
    ),
    'codex-rs/tui/src/snapshots/codex_tui__update_prompt__tests__update_picker_selected_28x12.snap': (
        '  Update available · 0.0.0\n  → 9.9.9\n'.encode("utf-8"),
        '  Update available ·\n  0.160.0 → 9.9.9\n'.encode("utf-8"),
    ),
    'codex-rs/tui/src/snapshots/codex_tui__startup_draft__layout__tests__owned_startup_layout.snap': (
        '  >_ OpenAI Codex (v<VERSION>)                      \n'.encode("utf-8"),
        '  >_ OpenAI Codex (v<VERSION>)                    \n'.encode("utf-8"),
    ),
}
TEST_MODULES = {
    "codex-rs/tui/src/progress_panel.rs": (
        '\n#[cfg(test)]\n#[path = "progress_panel_tests.rs"]\nmod tests;\n',
        '\n#[cfg(test)]\n#[path = "progress_panel_discovery_tests.rs"]\nmod discovery_tests;\n',
    ),
    "codex-rs/tui/src/chatwidget.rs": (
        '\n#[cfg(test)]\n#[path = "chatwidget/progress_panel_integration_tests.rs"]\nmod progress_panel_integration_tests;\n',
    ),
}


def patch_for(relative: str, before: bytes | None, after: bytes) -> str:
    before_lines = (
        before.decode("utf-8").splitlines(keepends=True)
        if before is not None
        else []
    )
    after_lines = after.decode("utf-8").splitlines(keepends=True)
    diff = "".join(
        line if line.endswith("\n") else line + "\n\\ No newline at end of file\n"
        for line in difflib.unified_diff(
            before_lines,
            after_lines,
            fromfile=f"a/{relative}" if before is not None else "/dev/null",
            tofile=f"b/{relative}",
        )
    )
    if not diff:
        return ""
    header = f"diff --git a/{relative} b/{relative}\n"
    if before is None:
        header += "new file mode 100644\n"
    return header + diff


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check that committed patches match the verified baseline and overlay without writing files",
    )
    args = parser.parse_args()
    check_source = runpy.run_path(str(ROOT / "scripts/check-source.py"))["check_source"]
    check_source(BASE, BASE / "MANIFEST.json")
    release, foundation, service, details, panel, regression, integration, combined = [], [], [], [], [], [], [], []
    for path in sorted(OVERLAY.rglob("*")):
        if not path.is_file() or (
            path.suffix not in {".rs", ".snap"} and path.name != "Cargo.lock"
        ):
            continue
        relative = path.relative_to(OVERLAY).as_posix()
        original = BASE / relative
        if path.is_symlink() or original.is_symlink():
            raise ValueError(f"Patch inputs must be regular files: {relative}")
        before = original.read_bytes() if original.exists() else None
        after = path.read_bytes()
        # Direct diffs avoid repeated paths, so the combined patch also reverses cleanly.
        combined.append(patch_for(relative, before, after))
        if relative in RELEASE_SNAPSHOT_PATHS:
            prefix = b"" if relative in RELEASE_BARE_VERSION_SNAPSHOT_PATHS else b"v"
            if before is None or before == after or after != before.replace(prefix + b"0.0.0", prefix + b"0.160.0"):
                raise ValueError(f"Release snapshot must contain only the pinned version update: {relative}")
            stage = release
        elif relative in RELEASE_EXACT_SNAPSHOTS:
            old_notice, replacement = RELEASE_EXACT_SNAPSHOTS[relative]
            if before is None or before.count(old_notice) != 1 or after != before.replace(old_notice, replacement, 1):
                raise ValueError(f"Release snapshot must contain only the approved exact transform: {relative}")
            stage = release
        elif path.name == "Cargo.lock":
            stage = release
        elif path.name in {"progress_panel_config.rs", "progress_panel_config_tests.rs"}:
            stage = foundation
        elif path.name == "progress_panel_service.rs":
            stage = service
        elif path.name == "progress_panel_details.rs":
            stage = details
        elif path.name in {"progress_panel_service_tests.rs", "progress_panel_integration_tests.rs"}:
            stage = integration
        elif path.suffix == ".snap" or path.name.endswith("_tests.rs"):
            stage = regression
        elif relative in TEST_MODULES:
            # Runtime stages omit test declarations until their test files are available.
            interim = after.decode("utf-8")
            service_test_declaration = '\n#[cfg(test)]\n#[path = "progress_panel_service_tests.rs"]\nmod service_tests;\n'
            has_service_tests = relative.endswith("progress_panel.rs") and service_test_declaration in interim
            if has_service_tests:
                interim = interim.replace(service_test_declaration, "", 1)
            for declaration in TEST_MODULES[relative]:
                if interim.count(declaration) != 1:
                    raise ValueError(f"Expected one test-module declaration in {relative}")
                interim = interim.replace(declaration, "", 1)
            interim_bytes = interim.encode("utf-8")
            panel.append(patch_for(relative, before, interim_bytes))
            test_stage = integration if relative.endswith("chatwidget.rs") else regression
            tests_bytes = after.replace(service_test_declaration.encode("utf-8"), b"", 1) if has_service_tests else after
            test_stage.append(patch_for(relative, interim_bytes, tests_bytes))
            if has_service_tests:
                integration.append(patch_for(relative, tests_bytes, after))
            continue
        else:
            stage = panel
        stage.append(patch_for(relative, before, after))
    outputs = (
        ("00-release-lockfile.patch", release),
        ("01-claim-schema.patch", foundation),
        ("02-service-client.patch", service),
        ("03-log-details.patch", details),
        ("04-embedded-panel.patch", panel),
        ("05-panel-regression-tests.patch", regression),
        ("06-integration-regression-tests.patch", integration),
        ("codex-progress-panel.patch", combined),
    )
    generated = {}
    for name, sections in outputs:
        data = "".join(sections).encode("utf-8")
        if name[:2].isdigit():
            changed_lines = sum(
                1 for line in data.splitlines()
                if (line.startswith(b"+") and not line.startswith(b"+++"))
                or (line.startswith(b"-") and not line.startswith(b"---"))
            )
            if changed_lines >= 800:
                raise ValueError(f"Review stage exceeds the 799 changed-line limit: {name} ({changed_lines})")
        generated[name] = data
    # Validate every stage before replacing any existing packaged artifact.
    expected_names = set(generated)
    stale = []
    if args.check:
        stale.extend(path.name for path in OUTPUT.glob("[0-9][0-9]-*.patch") if path.name not in expected_names)
        for name, data in generated.items():
            target = OUTPUT / name
            if not target.is_file() or target.read_bytes() != data:
                stale.append(name)
    else:
        OUTPUT.mkdir(exist_ok=True)
        for previous in OUTPUT.glob("[0-9][0-9]-*.patch"):
            if previous.name not in expected_names:
                previous.unlink()
        for name, data in generated.items():
            (OUTPUT / name).write_bytes(data)
    if stale:
        print(
            f"Patches are missing or stale: {', '.join(stale)}. Run scripts/generate-patch.py.",
            file=sys.stderr,
        )
        return 1
    action = "Verified" if args.check else "Generated"
    print(f"{action} release, schema, service, log details, panel, regression, integration, and combined patches.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, TypeError) as error:
        print(f"Patch generation failed: {error}", file=sys.stderr)
        sys.exit(1)
