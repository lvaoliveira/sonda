#!/bin/sh
# Fails when sonda's scan of its own code finds a function over the
# complexity thresholds (CONTRIBUTING.md, "No function over the complexity
# thresholds"): cognitive complexity over 15, in any language, and Python's
# function complexity.
# Each one is listed, and in GitHub Actions annotated on its line, so a
# pull request can't add one for a later pull request to refactor.
#
# Usage: scripts/check-complexity.sh REPORT.json, a report from
#   sonda scan . --no-gate -f json -o REPORT.json
set -eu

[ $# -eq 1 ] || { echo "usage: check-complexity.sh REPORT.json" >&2; exit 2; }
report=$1
rules='["common/cognitive-complexity", "py/function-complexity"]'

jq -e '.issues | type == "array"' "$report" > /dev/null 2>&1 ||
  { echo "check-complexity: $report isn't a sonda JSON report" >&2; exit 2; }
found=$(jq -r --argjson rules "$rules" \
  '.issues[] | select(.rule as $r | $rules | index($r)) | [.path, (.line | tostring), .message] | @tsv' \
  "$report")

if [ -z "$found" ]; then
  echo "check-complexity: no function over the complexity thresholds"
  exit 0
fi
echo "check-complexity: split these functions (CONTRIBUTING.md, \"No function over the complexity thresholds\"):" >&2
printf '%s\n' "$found" | while IFS="$(printf '\t')" read -r path line message; do
  echo "  $path:$line: $message" >&2
  if [ "${GITHUB_ACTIONS:-}" = true ]; then
    echo "::error file=$path,line=$line,title=Too complex::$message"
  fi
done
exit 1
