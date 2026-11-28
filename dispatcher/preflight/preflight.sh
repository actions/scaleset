#!/bin/bash
# Prepares the per-repository language cache before a runner accepts a job:
# checks that the host path is the shared cache (filesystem type and marker
# file), creates <root>/language-caches/<scope>/{uv,go-build,go-mod} and the
# per-pod workspace, then proves that the runner user can write, rename and
# list in every directory.
#
# Environment: CACHE_ROOT (mount point of the host path), CACHE_SCOPE
# (repository), POD_UID, RUNNER_NODE_NAME, CACHE_SERVER_NODE (node that holds
# the cache locally; every other node mounts it over NFS), CACHE_MARKER
# (marker file name, default .arc-runner-cache).
set -euo pipefail
root="${CACHE_ROOT:-/mnt/nfs}"
marker="${CACHE_MARKER:-.arc-runner-cache}"
if [ -n "${CACHE_SERVER_NODE:-}" ] && [ "${RUNNER_NODE_NAME:-}" = "${CACHE_SERVER_NODE}" ]; then
  backend=local
else
  backend=nfs
fi
filesystem=$(timeout -k 2s 5s findmnt -n -o FSTYPE -T "$root")
case "$backend:$filesystem" in
  nfs:nfs|nfs:nfs4|local:ext4|local:xfs) ;;
  *) echo "Language cache filesystem ($filesystem) does not match the $backend backend of node ${RUNNER_NODE_NAME:-unknown}." >&2; exit 1 ;;
esac
if [ ! -f "$root/$marker" ]; then
  echo "Shared runner cache is not mounted on node ${RUNNER_NODE_NAME:-unknown} (marker missing)." >&2
  exit 1
fi
CACHE_ROOT="$root" timeout -k 2s 15s python3 - <<'PYCODE'
import os
import re
import tempfile
from pathlib import Path

root = os.environ["CACHE_ROOT"]
scope = os.environ["CACHE_SCOPE"]
if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]*", scope):
    raise SystemExit("Invalid cache namespace")
pod_uid = os.environ["POD_UID"]
if not re.fullmatch(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", pod_uid):
    raise SystemExit("Invalid pod UID")
flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW

def directory(parent, name, mode):
    try:
        fd = os.open(name, flags, dir_fd=parent)
    except FileNotFoundError:
        try:
            os.mkdir(name, mode=mode, dir_fd=parent)
        except FileExistsError:
            pass
        fd = os.open(name, flags, dir_fd=parent)
    try:
        # NFSv4 can display an unmapped owner as nobody;
        # chmod and the I/O probe verify the actual AUTH_SYS identity.
        os.fchmod(fd, mode)
    except BaseException:
        os.close(fd)
        raise
    return fd

mount = os.open(root, flags)
parent = directory(mount, "language-caches", 0o755)
repo = directory(parent, scope, 0o755)
for name in ("uv", "go-build", "go-mod"):
    os.close(directory(repo, name, 0o770))
pods = directory(repo, "pods", 0o770)
workspace = directory(pods, pod_uid, 0o770)
for name in ("cache",):
    os.close(directory(workspace, name, 0o770))
os.close(workspace)
os.close(pods)
for fd in (repo, parent, mount):
    os.close(fd)
# Test actual runner permissions, not just root's ability to write.
base = Path(root) / "language-caches" / scope
probe_paths = [base / name for name in ("uv", "go-build", "go-mod")]
probe_paths += [base / "pods" / pod_uid / name for name in ("cache",)]
for cache in probe_paths:
    with tempfile.TemporaryDirectory(prefix=".nfs-preflight-", dir=cache) as scratch:
        probe = Path(scratch)
        nested = probe / "nested"
        nested.mkdir()
        item = nested / "value"
        item.write_text("preflight\n")
        item.rename(nested / "renamed")
        if (nested / "renamed").read_text() != "preflight\n":
            raise RuntimeError("NFS read mismatch")
        if sorted(p.name for p in nested.iterdir()) != ["renamed"]:
            raise RuntimeError("NFS nested listing mismatch")
        if sorted(p.name for p in probe.iterdir()) != ["nested"]:
            raise RuntimeError("NFS listing mismatch")
    print(f"NFS cache ready for uid={os.getuid()}: {cache}")
PYCODE
