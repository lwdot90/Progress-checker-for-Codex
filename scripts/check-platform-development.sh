#!/usr/bin/env bash
# Diagnostic subset only. Original full engineering acceptance remains required.
# Execute through the checker only after exact human CLI approval.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
source scripts/prototype-env.sh
export CARGO_TARGET_DIR="$PROTOTYPE_ROOT/.local/checker-target"
run_cargo_tests() {
  source scripts/prototype-env.sh
  local diagnostic_output
  diagnostic_output="$(mktemp)"
  printf 'Development filter: %s\n' "$*"
  if cargo test --offline --locked "$@" 2>&1 | tee "$diagnostic_output"; then
    if ! python3 - "$diagnostic_output" <<'CHECK_COUNT'
import re, sys
from pathlib import Path
text = Path(sys.argv[1]).read_text()
if not re.search(r'test result: ok\. [1-9][0-9]* passed;', text):
    raise SystemExit('FAIL: development filter selected no passing tests')
CHECK_COUNT
    then
      rm -f -- "$diagnostic_output"
      return 1
    fi
  else
    rm -f -- "$diagnostic_output"
    return 1
  fi
  rm -f -- "$diagnostic_output"
}
for suite in platform:: environment:: fingerprint:: engine::environment_framing_tests; do
  run_cargo_tests -p checker-core --lib "$suite"
 done
for case_name in strips_terminal_sequences_controls_and_redacts_secrets credential_normalization_preserves_newlines_and_removes_controls overlapping_credentials_do_not_expose_suffixes_or_rewrite_markers crossing_credential_intervals_hide_the_entire_union credential_split_at_capture_limit_is_hidden_and_output_stays_bounded split_utf8_at_capture_limit_cannot_expose_credential_prefix oversized_output_is_drained_and_bounded malformed_utf8_cannot_expand_past_the_display_limit only_final_trusted_exit_code_confirms_successful_sandbox_launch; do
  run_cargo_tests -p checker-core --lib "runner::tests::$case_name" -- --exact
 done
run_cargo_tests -p checker-global
run_cargo_tests -p checker-mcp
python3 scripts/test-native-packaging.py
python3 scripts/test-ubuntu-qualification.py
python3 scripts/test-platform-support.py
python3 scripts/test-windows-qualification.py
python3 scripts/test-engineering-recipient.py
python3 scripts/test-gateway-stdio.py
python3 scripts/check-native-source-artifacts.py
printf '%s\n' 'PASS: platform development subset; full host security, native runtime and recipient qualification remain separately required.'
