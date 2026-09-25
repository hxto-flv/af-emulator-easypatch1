#!/usr/bin/env python3
"""
Generate the local RSA key pair used by the Assault Fire PH emulator.

This creates:
  server/PRIVATE.PEM       -> private key used by the emulator (KEEP PRIVATE)
  generated/APClient.dat   -> matching public key for TCLS/config/APClient.dat

Assault Fire PH's legacy AUTH protocol uses RSA-1024. That size is intentionally
used here for client compatibility only; do not reuse this key for modern
security-sensitive applications.
"""

from __future__ import annotations

import argparse
import shutil
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PRIVATE = REPO_ROOT / "server" / "PRIVATE.PEM"
DEFAULT_PUBLIC = REPO_ROOT / "generated" / "APClient.dat"


def write_keypair(private_path: Path, public_path: Path, force: bool) -> None:
    if not force:
        existing = [p for p in (private_path, public_path) if p.exists()]
        if existing:
            names = "\n".join(f"  - {p}" for p in existing)
            raise SystemExit(
                "Refusing to overwrite existing key file(s):\n"
                f"{names}\n\n"
                "Use --force only if you intentionally want a NEW key pair.\n"
                "Remember: if the private key changes, APClient.dat must also "
                "be replaced with the matching public key."
            )

    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
    )

    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_path.write_bytes(private_pem)
    public_path.write_bytes(public_pem)

    # The known PH APClient.dat PEM is 272 bytes for this RSA-1024/SPKI format.
    if len(public_pem) != 272:
        raise SystemExit(
            f"Unexpected public PEM length: {len(public_pem)} bytes (expected 272)"
        )

    print("[OK] Generated a matching Assault Fire PH local RSA-1024 key pair.")
    print()
    print("[PRIVATE - SERVER]")
    print(f"  {private_path}")
    print("  Keep this file private. Never commit or upload it.")
    print()
    print("[PUBLIC - CLIENT]")
    print(f"  {public_path}")
    print("  This is the matching public PEM used as TCLS/config/APClient.dat.")


def install_public_key(public_path: Path, client_config_dir: Path) -> None:
    if not public_path.is_file():
        raise SystemExit(f"Public key not found: {public_path}")

    client_config_dir = client_config_dir.expanduser().resolve()
    if not client_config_dir.is_dir():
        raise SystemExit(
            "Client config folder does not exist:\n"
            f"  {client_config_dir}\n\n"
            "Point --client-config-dir at the folder containing APClient.dat."
        )

    dest = client_config_dir / "APClient.dat"

    if dest.exists():
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup = client_config_dir / f"APClient.dat.backup_{stamp}"
        shutil.copy2(dest, backup)
        print(f"[BACKUP] {dest}")
        print(f"      -> {backup}")

    shutil.copy2(public_path, dest)
    print(f"[OK] Installed matching public key:")
    print(f"  {dest}")


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Generate the local RSA-1024 key pair used by af-emulator."
    )
    ap.add_argument(
        "--private-out",
        type=Path,
        default=DEFAULT_PRIVATE,
        help=f"private key output (default: {DEFAULT_PRIVATE})",
    )
    ap.add_argument(
        "--public-out",
        type=Path,
        default=DEFAULT_PUBLIC,
        help=f"public APClient.dat output (default: {DEFAULT_PUBLIC})",
    )
    ap.add_argument(
        "--client-config-dir",
        type=Path,
        help=(
            "optional Assault Fire TCLS/config folder; when supplied, "
            "the generated APClient.dat is copied there after backing up "
            "any existing file"
        ),
    )
    ap.add_argument(
        "--force",
        action="store_true",
        help="replace an existing generated key pair",
    )
    args = ap.parse_args()

    private_path = args.private_out.expanduser().resolve()
    public_path = args.public_out.expanduser().resolve()

    write_keypair(private_path, public_path, args.force)

    if args.client_config_dir:
        print()
        install_public_key(public_path, args.client_config_dir)

    print()
    print("Next:")
    print("  1. Make sure the client uses the matching APClient.dat public PEM.")
    print("  2. Start: python .\\server\\assaultfire_server_v143b.py")
    print("  3. Look for: [BOOT] Loaded RSA private key from ...")


if __name__ == "__main__":
    main()
