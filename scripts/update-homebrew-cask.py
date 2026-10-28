#!/usr/bin/env python3
"""Replace the version and sha256 in the CertRev Homebrew cask."""

import os
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text()
version = os.environ["VERSION"]
sha = os.environ["SHA256"]
updated = re.sub(r'version "[^"]+"', f'version "{version}"', text, count=1)
updated = re.sub(r'sha256 "[^"]+"', f'sha256 "{sha}"', updated, count=1)
if updated == text:
    raise SystemExit("cask version and sha256 were already current, or the file shape changed")
path.write_text(updated)
