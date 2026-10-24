#!/usr/bin/env python3
"""Root-only synthetic fixture; execute a Rust regression test as a nonroot UID."""
import os
import pathlib
import subprocess
import sys
import tempfile

binary = str(pathlib.Path(sys.argv[1]).resolve())
uid = int(sys.argv[2])
if os.geteuid() != 0 or uid <= 0:
    sys.exit("requires root and a nonroot target UID")
with tempfile.TemporaryDirectory(prefix="vpn-credential-test-") as temporary:
    folder = pathlib.Path(temporary)
    for name in ("test", "unreadable"):
        path = folder / name
        path.write_bytes(bytes([7]) * 32)
        path.chmod(0o400)
    folder.chmod(0o500)
    for path, permission in ((folder, "rx"), (folder / "test", "r")):
        subprocess.run(["setfacl", "-m", f"u:{uid}:{permission}", str(path)], check=True)
    env = dict(os.environ, VPN_CREDENTIAL_TEST_DIR=str(folder))
    subprocess.run(["setpriv", f"--reuid={uid}", f"--regid={uid}", "--clear-groups",
                    binary, "credentials::tests::root_owned_systemd_layout", "--exact", "--ignored"],
                   env=env, check=True)
