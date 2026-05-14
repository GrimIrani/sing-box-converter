"""
Runtime management: sing-box binary and geo database download/caching.

Cache directory: ~/.singboxconverter/
    bin/sing-box       (or sing-box.exe on Windows)
    db/geoip.db
    db/geosite.db
"""

import io
import json
import os
import platform
import sys
import tarfile
import zipfile
from pathlib import Path
from urllib.request import urlopen, Request

CACHE_DIR = Path.home() / ".singboxconverter"
BIN_DIR = CACHE_DIR / "bin"
DB_DIR = CACHE_DIR / "db"

SING_BOX_REPO = "SagerNet/sing-box"
GEOIP_URL = "https://github.com/SagerNet/sing-geoip/releases/latest/download/geoip.db"
GEOSITE_URL = "https://github.com/SagerNet/sing-geosite/releases/latest/download/geosite.db"


def _fetch(url):
    req = Request(url, headers={"User-Agent": "singboxconverter"})
    with urlopen(req, timeout=120) as resp:
        return resp.read()


def _platform():
    os_map = {"linux": "linux", "darwin": "darwin", "win32": "windows"}
    os_name = os_map.get(sys.platform)
    if not os_name:
        raise RuntimeError(f"Unsupported OS: {sys.platform}")

    arch_map = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }
    arch = arch_map.get(platform.machine().lower())
    if not arch:
        raise RuntimeError(f"Unsupported architecture: {platform.machine()}")

    return os_name, arch


def _bin_name():
    return "sing-box.exe" if sys.platform == "win32" else "sing-box"


def binary_path():
    """Return path to cached sing-box binary, or None."""
    p = BIN_DIR / _bin_name()
    return str(p) if p.exists() else None


def download_binary(version=None):
    """Download sing-box binary for current platform.

    Args:
        version: specific version string (e.g. "1.9.0"), or None for latest.

    Returns:
        Path to the downloaded binary.
    """
    os_name, arch = _platform()
    BIN_DIR.mkdir(parents=True, exist_ok=True)

    if version:
        api_url = f"https://api.github.com/repos/{SING_BOX_REPO}/releases/tags/v{version}"
    else:
        api_url = f"https://api.github.com/repos/{SING_BOX_REPO}/releases/latest"

    release = json.loads(_fetch(api_url))

    ext = ".zip" if os_name == "windows" else ".tar.gz"
    pattern = f"-{os_name}-{arch}"

    asset_url = None
    for asset in release.get("assets", []):
        name = asset["name"]
        if pattern in name and name.endswith(ext):
            asset_url = asset["browser_download_url"]
            break

    if not asset_url:
        raise RuntimeError(f"No sing-box binary found for {os_name}/{arch}")

    print(f"Downloading sing-box ({os_name}/{arch})...")
    data = _fetch(asset_url)

    name = _bin_name()

    if ext == ".tar.gz":
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
            for member in tar.getmembers():
                if os.path.basename(member.name) == "sing-box":
                    f = tar.extractfile(member)
                    if f:
                        (BIN_DIR / name).write_bytes(f.read())
                    break
    else:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for entry in zf.namelist():
                if os.path.basename(entry) == "sing-box.exe":
                    (BIN_DIR / name).write_bytes(zf.read(entry))
                    break

    path = BIN_DIR / name
    if os_name != "windows":
        path.chmod(0o755)

    print(f"Installed: {path}")
    return str(path)


def ensure_binary():
    """Return binary path, downloading if not cached."""
    p = binary_path()
    return p if p else download_binary()


def download_databases():
    """Download geoip.db and geosite.db if not cached.

    Returns:
        (geoip_path, geosite_path) tuple.
    """
    DB_DIR.mkdir(parents=True, exist_ok=True)
    paths = {}

    for name, url in [("geoip.db", GEOIP_URL), ("geosite.db", GEOSITE_URL)]:
        dest = DB_DIR / name
        if not dest.exists():
            print(f"Downloading {name}...")
            dest.write_bytes(_fetch(url))
            print(f"Saved: {dest}")
        paths[name] = str(dest)

    return paths["geoip.db"], paths["geosite.db"]


def ensure_databases():
    """Return (geoip_path, geosite_path), downloading if needed."""
    return download_databases()


def setup():
    """Download sing-box binary.

    Returns:
        Path to the sing-box binary.
    """
    return ensure_binary()
