#!/usr/bin/env python3
"""Write image.tag and image.digest of a Helm values file (cd.yml).

usage: set-image.py [--no-downgrade] <values.yaml> <X.Y.Z> <sha256:...>

Only the two lines under the top-level `image:` key change; comments and
every other value are kept. With --no-downgrade, a version older than the
one already written leaves the file untouched.
"""

import re
import sys
from pathlib import Path

args = sys.argv[1:]
no_downgrade = "--no-downgrade" in args
args = [a for a in args if a != "--no-downgrade"]
if len(args) != 3:
    sys.exit(__doc__)
path, version, digest = Path(args[0]), args[1], args[2]
if not re.fullmatch(r"\d+\.\d+\.\d+", version):
    sys.exit(f"version {version!r} is not X.Y.Z")
if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
    sys.exit(f"digest {digest!r} is not sha256:<64 hex>")

src = path.read_text(encoding="utf-8")
block = re.search(r"^image:\n((?:[ #].*\n|\n)*)", src, re.MULTILINE)
if not block:
    sys.exit(f"no top-level image: key in {path}")
body = block.group(1)
tag_line = re.compile(r'^(  tag: )"([^"]*)"', re.MULTILINE)
digest_line = re.compile(r'^(  digest: )"([^"]*)"', re.MULTILINE)
current = tag_line.search(body)
if not current or not digest_line.search(body):
    sys.exit(f'image.tag and image.digest must be quoted strings in {path}')


def parse(v):
    return tuple(int(x) for x in v.split("."))


if no_downgrade and re.fullmatch(r"\d+\.\d+\.\d+", current.group(2)):
    if parse(current.group(2)) > parse(version):
        print(f"{path}: {current.group(2)} is newer than {version}, unchanged")
        sys.exit(0)

body = tag_line.sub(rf'\g<1>"{version}"', body, count=1)
body = digest_line.sub(rf'\g<1>"{digest}"', body, count=1)
path.write_text(src[: block.start(1)] + body + src[block.end(1) :], encoding="utf-8")
print(f"{path}: image {version} {digest}")
