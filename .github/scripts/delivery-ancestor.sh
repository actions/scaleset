#!/usr/bin/env bash
# Walks back from a commit of main over the commits written by the delivery
# itself (release.yml, cd.yml), which carry no ci-dispatcher run:
#   - release commit: "chore(release): dispatcher-v..." touching only
#     CHANGELOG.md and charts/ci-dispatcher/Chart.yaml;
#   - candidate / promotion commit: by github-actions[bot], touching only
#     acceptance/values.yaml or charts/ci-dispatcher/values.yaml.
#
# usage:
#   delivery-ancestor.sh validated <commit>
#       prints the first ancestor (commit included) with a successful push run
#       of ci-dispatcher.yml on main; fails if a commit of another kind is met.
#       Needs GH_TOKEN and GITHUB_REPOSITORY.
#   delivery-ancestor.sh reaches <commit> <target>
#       succeeds when <target> is reached from <commit> over candidate and
#       promotion commits only.
set -euo pipefail

mode=${1:-}
commit=${2:-}
[ -n "$mode" ] && [ -n "$commit" ] || { echo "ERREUR: usage: $0 validated <commit> | reaches <commit> <target>" >&2; exit 2; }

only_files() { # <commit> <regex of allowed paths>
  local files
  files=$(git diff-tree --no-commit-id --name-only -r "$1")
  [ -n "$files" ] && ! grep -vxE "$2" <<< "$files" > /dev/null
}
is_bot_values() {
  [ "$(git log -1 --format=%ae "$1")" = "github-actions[bot]@users.noreply.github.com" ] &&
    only_files "$1" 'acceptance/values\.yaml|charts/ci-dispatcher/values\.yaml'
}
is_release() {
  git log -1 --format=%s "$1" | grep -Eq '^chore\(release\): dispatcher-v[0-9]+\.[0-9]+\.[0-9]+ ' &&
    only_files "$1" 'CHANGELOG\.md|charts/ci-dispatcher/Chart\.yaml'
}
validated() {
  [ "$(gh api "repos/$GITHUB_REPOSITORY/actions/workflows/ci-dispatcher.yml/runs?branch=main&event=push&head_sha=$1&status=success&per_page=1" --jq .total_count)" -ge 1 ]
}

sha=$(git rev-parse "$commit^{commit}")
case "$mode" in
  validated)
    for _ in $(seq 1 30); do
      if validated "$sha"; then echo "$sha"; exit 0; fi
      if is_release "$sha" || is_bot_values "$sha"; then sha=$(git rev-parse "$sha^"); continue; fi
      echo "ERREUR: $sha is neither validated on main nor a delivery commit" >&2
      exit 1
    done ;;
  reaches)
    target=$(git rev-parse "${3:?target missing}^{commit}")
    for _ in $(seq 1 30); do
      [ "$sha" = "$target" ] && exit 0
      is_bot_values "$sha" || exit 1
      sha=$(git rev-parse "$sha^")
    done
    exit 1 ;;
  *) echo "ERREUR: unknown mode $mode" >&2; exit 2 ;;
esac
echo "ERREUR: no validated commit within 30 ancestors" >&2
exit 1
