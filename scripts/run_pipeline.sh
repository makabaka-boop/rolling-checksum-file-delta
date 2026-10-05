#!/usr/bin/env sh
# Orchestrate signature -> delta -> apply with per-stage directory isolation.
#
# Usage:
#   scripts/run_pipeline.sh [BASELINE NEWFILE] [--host]
#
# With no arguments a deterministic demo pair (including a block move and an
# insertion) is generated under ./stages/.
#
# --host runs rdiff.py directly with python3 instead of docker compose.
#
# The stage directories enforce the read set of every command:
#   1_sig_in/    : baseline
#   2_delta_in/  : signature + newfile  (NO baseline)
#   3_apply_in/  : baseline + patch     (NO newfile)
# The script copies only the allowed artefact into each next stage.

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

HOST=0
if [ "${1:-}" = "--host" ]; then
    HOST=1; shift
elif [ "${3:-}" = "--host" ]; then
    HOST=1; shift
fi

BASELINE=${1:-}
NEWFILE=${2:-}

S1_IN=stages/1_sig_in
S1_OUT=stages/1_sig_out
S2_IN=stages/2_delta_in
S2_OUT=stages/2_delta_out
S3_IN=stages/3_apply_in
S3_OUT=stages/3_apply_out

rm -rf stages
mkdir -p "$S1_IN" "$S1_OUT" "$S2_IN" "$S2_OUT" "$S3_IN" "$S3_OUT"

if [ -z "$BASELINE" ]; then
    # Generate demo data with python (same LCG used by the test suite).
    python3 scripts/make_demo.py "$S1_IN/baseline" "$S2_IN/newfile"
else
    cp -- "$BASELINE" "$S1_IN/baseline"
    cp -- "$NEWFILE" "$S2_IN/newfile"
fi

if [ "$HOST" -eq 1 ]; then
    python3 rdiff.py signature "$S1_IN/baseline"  "$S1_OUT/signature"
    cp "$S1_OUT/signature" "$S2_IN/signature"
    python3 rdiff.py delta     "$S2_IN/signature"  "$S2_IN/newfile" "$S2_OUT/patch"
    cp "$S1_IN/baseline" "$S3_IN/baseline"
    cp "$S2_OUT/patch"   "$S3_IN/patch"
    python3 rdiff.py apply     "$S3_IN/baseline"  "$S3_IN/patch"    "$S3_OUT/target"
else
    docker compose run --rm signature
    cp "$S1_OUT/signature" "$S2_IN/signature"
    docker compose run --rm delta
    cp "$S1_IN/baseline" "$S3_IN/baseline"
    cp "$S2_OUT/patch"   "$S3_IN/patch"
    docker compose run --rm apply
fi

# Byte-exact verification.
cmp "$S2_IN/newfile" "$S3_OUT/target"
echo
echo "OK: $S3_OUT/target is byte-identical to the new file."
echo "baseline size : $(wc -c < "$S1_IN/baseline") bytes"
echo "new file size : $(wc -c < "$S2_IN/newfile") bytes"
echo "patch size    : $(wc -c < "$S2_OUT/patch") bytes"

# Show that forbidden inputs are absent from the isolated stage dirs.
[ ! -e "$S2_IN/baseline" ] && echo "isolation: delta stage has no baseline"
[ ! -e "$S3_IN/newfile" ]  && echo "isolation: apply stage has no new file"
