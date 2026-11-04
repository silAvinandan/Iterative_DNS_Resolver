#!/usr/bin/env bash
# Cross-checks the resolver against `dig +trace` for every line in a domains file.
#
#   validation/validate.sh [domains-file]          (run from the project root, after `mvn clean package`)
#
# For each "name type" it compares:
#   * the delegation chain (zones walked, e.g. . > com. > example.com.)   -> must MATCH
#   * the final A/AAAA address set                                          -> may legitimately differ
#                                                                              (load-balancing / DNS changes)
# and records upstream query counts and latency. Results go to validation/results-<timestamp>/.
#
# Override the commands for testing/other layouts:
#   RESOLVER_CMD="java -jar target/dns-resolver-1.0.0.jar"   DIG=dig
set -u

cd "$(dirname "$0")/.." || exit 2
RESOLVER_CMD=${RESOLVER_CMD:-"java -jar target/dns-resolver-1.0.0.jar"}
DIG=${DIG:-dig}
DOMAINS=${1:-validation/domains.txt}
OUT="validation/results-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"
SUMMARY="$OUT/summary.md"

command -v "$DIG" >/dev/null 2>&1 || { echo "dig not found (install dnsutils/bind-utils)"; exit 2; }

printf '| domain | type | chain vs dig | answers vs dig | resolver status | upstream queries | dig "Received" lines | elapsed ms |\n' > "$SUMMARY"
printf '|---|---|---|---|---|---|---|---|\n' >> "$SUMMARY"

match=0; diff=0; failed=0; total=0

while read -r name type _; do
  [[ -z "${name:-}" || "$name" == \#* ]] && continue
  type=${type:-A}
  total=$((total+1))
  tag="${name//[^A-Za-z0-9.-]/_}_${type}"

  # ---- our resolver
  $RESOLVER_CMD "$name" "$type" --stats > "$OUT/$tag.resolver.txt" 2> "$OUT/$tag.resolver.err"
  stats=$(grep '^STATS ' "$OUT/$tag.resolver.txt" | tail -1)
  status=$(sed -n 's/.* status=\([A-Z]*\).*/\1/p' <<<"$stats")
  queries=$(sed -n 's/.* upstream_queries=\([0-9]*\).*/\1/p' <<<"$stats")
  elapsed=$(sed -n 's/.* elapsed_ms=\([0-9]*\).*/\1/p' <<<"$stats")
  my_chain=$(sed -n 's/^Delegation chain: //p' "$OUT/$tag.resolver.txt" | sed 's/ > />/g')
  my_answers=$(awk '/^Answer:/{f=1;next} /^STATS/{f=0} f && $3=="IN" && $4=="'"$type"'" {print $NF}' "$OUT/$tag.resolver.txt" | sort -u | paste -sd, -)

  # ---- dig +trace
  $DIG +trace +nodnssec "$name" "$type" > "$OUT/$tag.dig.txt" 2>&1
  dig_chain=$(grep -v '^;' "$OUT/$tag.dig.txt" | awk 'NF>=5 && $4=="NS" {print $1}' | uniq | paste -sd'>' -)
  dig_answers=$(grep -v '^;' "$OUT/$tag.dig.txt" | awk -v n="${name%.}." -v t="$type" 'tolower($1)==tolower(n) && $4==t {print $NF}' | sort -u | paste -sd, -)
  dig_received=$(grep -c '^;; Received' "$OUT/$tag.dig.txt")

  # ---- compare
  if [[ "${status:-}" != "OK" ]]; then
    chain_result="RESOLVER-FAILED"; failed=$((failed+1))
  elif [[ "$my_chain" == "$dig_chain" ]]; then
    chain_result="MATCH"; match=$((match+1))
  else
    chain_result="DIFF"; diff=$((diff+1))
    { echo "mine: $my_chain"; echo "dig:  $dig_chain"; } > "$OUT/$tag.chain-diff.txt"
  fi
  if [[ "$type" != "A" && "$type" != "AAAA" ]]; then ans_result="n/a ($type)"
  elif [[ -z "$dig_answers" ]]; then ans_result="n/a (dig stopped, e.g. at a CNAME)"
  elif [[ "$my_answers" == "$dig_answers" ]]; then ans_result="same"
  else ans_result="differs (check: $my_answers vs $dig_answers)"; fi

  printf '| %s | %s | %s | %s | %s | %s | %s | %s |\n' "$name" "$type" "$chain_result" "$ans_result" \
    "${status:-?}" "${queries:-?}" "$dig_received" "${elapsed:-?}" >> "$SUMMARY"
  printf '%-45s %-6s chain=%-16s answers=%s\n' "$name" "$type" "$chain_result" "$ans_result"
done < "$DOMAINS"

{
  echo
  echo "Totals: $total queries, chain MATCH=$match, DIFF=$diff, resolver FAILED=$failed"
  echo
  echo "Notes: dig's 'Received' count includes its first query for the root NS set sent to your local"
  echo "resolver, so compare it with 'upstream queries' + 1. Answer differences are expected for"
  echo "load-balanced names; chain DIFFs are not - see <name>_<type>.chain-diff.txt."
} >> "$SUMMARY"
echo; echo "Totals: $total, MATCH=$match, DIFF=$diff, FAILED=$failed   (details: $SUMMARY)"
[[ $diff -eq 0 && $failed -eq 0 ]]
