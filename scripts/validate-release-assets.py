#!/usr/bin/env python3
"""Validate privately signed public patch assets. Never create signatures."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

MANIFEST_NAME = "pride-manifest.v1.json"
SIGNATURE_NAME = "pride-manifest.v1.json.sig"
VERIFY_NAME = "update-verify.v1"
ASSETS_NAME = "pride-assets.v1.json"
OBJECT_RE = re.compile(r"^obj-([a-f0-9]{64})$")
HEX64 = re.compile(r"^[a-f0-9]{64}$")
HEX128 = re.compile(r"^[a-f0-9]{128}$")


def fail(reason: str) -> None:
    print("OK=NO", file=sys.stdout)
    print("reason=" + reason, file=sys.stdout)
    sys.exit(2)


def load_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def assert_safe_path(posix: str) -> None:
    if not posix or posix != posix.strip():
        fail("UNSAFE_PATH_EMPTY")
    if "\\" in posix or ":" in posix or posix.startswith("/") or posix.startswith("//"):
        fail("UNSAFE_PATH_ABSOLUTE:" + posix)
    if ".." in posix.split("/"):
        fail("UNSAFE_PATH_TRAVERSAL:" + posix)
    if posix.endswith("/") or "//" in posix:
        fail("UNSAFE_PATH_SLASH:" + posix)


def parse_verify_pub(text: str) -> bytes:
    if "SEED_HEX=" in text or "PKCS8_HEX=" in text:
        fail("PRIVATE_IN_VERIFY")
    if "DOMAIN=UPDATE_VERIFY" not in text:
        fail("VERIFY_DOMAIN")
    if "ALGORITHM=Ed25519" not in text:
        fail("VERIFY_ALG")
    pub_hex = None
    for line in text.replace("\r\n", "\n").split("\n"):
        if line.startswith("PUB_HEX="):
            pub_hex = line[len("PUB_HEX=") :].strip()
    if not pub_hex or not HEX64.match(pub_hex):
        fail("VERIFY_PUB")
    return bytes.fromhex(pub_hex)


def verify_ed25519(pub: bytes, message: bytes, signature: bytes) -> None:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        fail("MISSING_CRYPTOGRAPHY")
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(signature, message)
    except InvalidSignature:
        fail("SIGNATURE")
    except Exception:
        fail("SIGNATURE_VERIFY_ERROR")


def allowed_name(name: str) -> bool:
    if name in (MANIFEST_NAME, SIGNATURE_NAME, VERIFY_NAME, ASSETS_NAME):
        return True
    return OBJECT_RE.match(name) is not None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--assets-dir", default="release-assets")
    parser.add_argument("--list-upload", action="store_true")
    args = parser.parse_args()
    root = Path(args.assets_dir)
    if not root.is_dir():
        fail("ASSETS_DIR_MISSING")

    names = sorted(p.name for p in root.iterdir() if p.is_file())
    if not names:
        fail("ASSETS_EMPTY")
    for name in names:
        lower = name.lower()
        if "signing" in lower or name == "update-signing.v1":
            fail("FORBIDDEN_NAME:" + name)
        if not allowed_name(name):
            fail("UNEXPECTED_FILE:" + name)
        if name.endswith(".json") or name.endswith(".sig") or name.endswith(".v1") or name.endswith(".txt"):
            text = load_text(root / name)
            for marker in ("SEED_HEX=", "PKCS8_HEX=", "gho_", "ghp_", "github_pat_"):
                if marker in text:
                    fail("SECRET_MARKER:" + name)

    man_path = root / MANIFEST_NAME
    sig_path = root / SIGNATURE_NAME
    ver_path = root / VERIFY_NAME
    if not man_path.is_file():
        fail("MISSING_MANIFEST")
    if not sig_path.is_file():
        fail("MISSING_SIGNATURE")
    if not ver_path.is_file():
        fail("MISSING_VERIFY")

    canonical = man_path.read_bytes()
    try:
        manifest = json.loads(canonical.decode("utf-8"))
    except Exception:
        fail("MANIFEST_JSON")
    if manifest.get("format") != "pride.client.manifest.v1":
        fail("MANIFEST_FORMAT")
    files = manifest.get("files")
    objects = manifest.get("objects")
    if not isinstance(files, list) or not files:
        fail("MANIFEST_FILES")
    if not isinstance(objects, list) or not objects:
        fail("MANIFEST_OBJECTS")

    obj_by_id = {}
    for obj in objects:
        oid = obj.get("id")
        osha = obj.get("sha256")
        if not isinstance(oid, str) or not HEX64.match(oid):
            fail("OBJECT_ID")
        if osha != oid:
            fail("OBJECT_ID_HASH_MISMATCH:" + oid)
        obj_file = root / ("obj-" + oid)
        if not obj_file.is_file():
            fail("MISSING_OBJECT:" + oid)
        actual = sha256_file(obj_file)
        if actual != oid:
            fail("OBJECT_BYTES_HASH:" + oid)
        obj_by_id[oid] = obj_file

    on_disk_objs = {p.name[4:] for p in root.iterdir() if p.is_file() and OBJECT_RE.match(p.name)}
    extra = on_disk_objs.difference(obj_by_id)
    if extra:
        fail("STALE_OBJECT:" + sorted(extra)[0])

    for item in files:
        path = item.get("path")
        oid = item.get("objectId")
        if not isinstance(path, str) or not isinstance(oid, str):
            fail("FILE_FIELDS")
        assert_safe_path(path)
        if oid not in obj_by_id:
            fail("FILE_OBJECT_MISSING:" + path)
        if path.lower() == "system/l2.ini":
            fail("PROTECTED_L2INI_PAYLOAD")

    if (root / ASSETS_NAME).is_file():
        try:
            idx = json.loads(load_text(root / ASSETS_NAME))
        except Exception:
            fail("ASSETS_JSON")
        mapped = idx.get("objects")
        if not isinstance(mapped, dict):
            fail("ASSETS_OBJECTS")
        for oid, fname in mapped.items():
            if oid not in obj_by_id or fname != ("obj-" + oid):
                fail("ASSETS_MAP:" + str(oid))

    sig_text = load_text(sig_path).strip()
    if not HEX128.match(sig_text):
        fail("SIGNATURE_FORMAT")
    pub = parse_verify_pub(load_text(ver_path))
    verify_ed25519(pub, canonical, bytes.fromhex(sig_text))

    upload = [MANIFEST_NAME, SIGNATURE_NAME]
    upload.extend("obj-" + oid for oid in sorted(obj_by_id))
    if (root / ASSETS_NAME).is_file():
        upload.append(ASSETS_NAME)
    upload.append(VERIFY_NAME)

    if args.list_upload:
        for name in upload:
            print(str((root / name).as_posix()))
        return 0

    obj_uploads = [n for n in upload if n.startswith("obj-")]
    if len(obj_uploads) != len(obj_by_id):
        fail("UPLOAD_OBJECT_COUNT")
    print("OK=YES")
    print("SIGNED_ASSETS_VALIDATION=PASS")
    print("ALL_OBJECTS_INCLUDED=YES")
    print("FILE_COUNT=" + str(len(files)))
    print("OBJECT_COUNT=" + str(len(obj_by_id)))
    print("MANIFEST_PATH=" + files[0].get("path", ""))
    for item in files:
        print("PLAYER_PATH=" + str(item.get("path", "")))
    for name in upload:
        print("UPLOAD_FILE=" + name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
