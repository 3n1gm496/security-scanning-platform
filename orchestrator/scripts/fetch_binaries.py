#!/usr/bin/env python3
"""Fetch release assets for nuclei, grype and zap and install them.
Best-effort helper used during Dockerfile build. Uses GitHub Releases API.
"""

import argparse
import os
import shutil
import stat
import sys
import tarfile
import tempfile
from pathlib import Path
from urllib.parse import urlparse
import zipfile

import requests

GITHUB_API = "https://api.github.com/repos/{owner}/{repo}/releases/tags/{tag}"
DOWNLOAD_DIR = tempfile.gettempdir()


def is_safe_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme == "https" and bool(parsed.netloc)


def is_within_directory(base: str, target: str) -> bool:
    base_path = Path(base).resolve()
    target_path = Path(target).resolve()
    try:
        target_path.relative_to(base_path)
        return True
    except ValueError:
        return False


def safe_extract_tar(archive: tarfile.TarFile, destination: str) -> None:
    for member in archive.getmembers():
        final_path = os.path.join(destination, member.name)
        if not is_within_directory(destination, final_path):
            raise ValueError(f"unsafe tar path: {member.name}")
    for member in archive.getmembers():
        archive.extract(member, destination)


def safe_extract_zip(archive: zipfile.ZipFile, destination: str) -> None:
    for member in archive.namelist():
        final_path = os.path.join(destination, member)
        if not is_within_directory(destination, final_path):
            raise ValueError(f"unsafe zip path: {member}")
    for member in archive.namelist():
        if member.endswith("/"):
            os.makedirs(os.path.join(destination, member), exist_ok=True)
            continue
        final_path = os.path.join(destination, member)
        os.makedirs(os.path.dirname(final_path), exist_ok=True)
        with archive.open(member) as src, open(final_path, "wb") as dst:
            shutil.copyfileobj(src, dst)


def download_url(url: str, dst: str) -> bool:
    if not is_safe_url(url):
        print(f"download rejected (non-https URL): {url}")
        return False
    try:
        response = requests.get(url, timeout=30, stream=True)
        response.raise_for_status()
        with open(dst, "wb") as out:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    out.write(chunk)
        return True
    except Exception as e:
        print(f"download failed {url}: {e}")
        return False


def pick_asset(release_json: dict, name_contains: tuple[str, ...]) -> str | None:
    for asset in release_json.get("assets", []):
        name = asset.get("name", "")
        lname = name.lower()
        if all(part in lname for part in name_contains):
            return asset.get("browser_download_url")
    return None


def get_release(owner: str, repo: str, tag: str) -> dict | None:
    url = GITHUB_API.format(owner=owner, repo=repo, tag=tag)
    if not is_safe_url(url):
        print(f"failed to fetch release metadata {owner}/{repo} {tag}: invalid URL")
        return None
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"failed to fetch release metadata {owner}/{repo} {tag}: {e}")
        return None


def ensure_executable(path: str) -> None:
    try:
        st = os.stat(path)
        os.chmod(path, st.st_mode | stat.S_IEXEC)
    except Exception:
        pass


def install_nuclei(version: str) -> None:
    # nuclei releases vary in naming; try several heuristics
    tag = f"v{version}"
    rel = get_release("projectdiscovery", "nuclei", tag)
    if not rel:
        print("nuclei: release metadata not found, skipping")
        return
    # prefer linux amd64 tar.gz
    url = pick_asset(rel, ("linux", "amd64")) or pick_asset(rel, ("linux", "64"))
    if not url:
        print("nuclei: no suitable asset found in release, skipping")
        return
    out = os.path.join(DOWNLOAD_DIR, "nuclei.tar.gz")
    print(f"nuclei: downloading {url} -> {out}")
    if not download_url(url, out):
        print("nuclei: download failed")
        return
    try:
        with tarfile.open(out, "r:gz") as tf:
            for member in tf.getmembers():
                if os.path.basename(member.name) == "nuclei":
                    safe_extract_tar(tf, "/usr/local/bin")
                    src = os.path.join("/usr/local/bin", member.name)
                    dst = "/usr/local/bin/nuclei"
                    try:
                        shutil.move(src, dst)
                    except Exception:
                        pass
                    ensure_executable(dst)
                    print("nuclei: installed to /usr/local/bin/nuclei")
                    break
    except Exception as e:
        print(f"nuclei: extraction failed: {e}")


def install_grype(version: str) -> None:
    tag = f"v{version}"
    rel = get_release("anchore", "grype", tag)
    if not rel:
        print("grype: release metadata not found, skipping")
        return
    url = pick_asset(rel, ("linux", "amd64")) or pick_asset(rel, ("linux", "amd64"))
    if not url:
        print("grype: no suitable asset found in release, skipping")
        return
    out = os.path.join(DOWNLOAD_DIR, "grype.tar.gz")
    print(f"grype: downloading {url} -> {out}")
    if not download_url(url, out):
        print("grype: download failed")
        return
    try:
        with tarfile.open(out, "r:gz") as tf:
            for member in tf.getmembers():
                if os.path.basename(member.name) == "grype":
                    safe_extract_tar(tf, "/usr/local/bin")
                    src = os.path.join("/usr/local/bin", member.name)
                    dst = "/usr/local/bin/grype"
                    try:
                        shutil.move(src, dst)
                    except Exception:
                        pass
                    ensure_executable(dst)
                    print("grype: installed to /usr/local/bin/grype")
                    break
    except Exception as e:
        print(f"grype: extraction failed: {e}")


def install_zap(version: str) -> None:
    tag = f"v{version}"
    rel = get_release("zaproxy", "zaproxy", tag)
    if not rel:
        print("zap: release metadata not found, skipping")
        return
    # look for a linux archive (zip or tar.gz)
    url = pick_asset(rel, ("linux", ".tar.gz")) or pick_asset(rel, ("linux", ".zip"))
    if not url:
        print("zap: no suitable linux asset found in release, skipping")
        return
    basename = os.path.basename(url)
    out = os.path.join(DOWNLOAD_DIR, basename)
    print(f"zap: downloading {url} -> {out}")
    if not download_url(url, out):
        print("zap: download failed")
        return
    try:
        if out.endswith(".zip"):
            with zipfile.ZipFile(out, "r") as zf:
                safe_extract_zip(zf, "/opt")
        else:
            # assume tar.gz
            with tarfile.open(out, "r:gz") as tf:
                safe_extract_tar(tf, "/opt")
        # try to find zap.sh
        for root, dirs, files in os.walk("/opt"):
            if "zap.sh" in files:
                src = os.path.join(root, "zap.sh")
                dst = "/usr/local/bin/zap.sh"
                try:
                    shutil.copy(src, dst)
                    ensure_executable(dst)
                    print(f"zap: installed zap.sh -> {dst}")
                except Exception as e:
                    print(f"zap: failed to install zap.sh: {e}")
                break
    except Exception as e:
        print(f"zap: extraction failed: {e}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--nuclei-version", default="", help="nuclei release version (no v prefix)")
    parser.add_argument("--grype-version", default="", help="grype release version (no v prefix)")
    parser.add_argument("--zap-version", default="", help="zap release version (no v prefix)")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("fetch_binaries: must run as root to install into /usr/local/bin and /opt")
        return 1

    if args.nuclei_version:
        try:
            install_nuclei(args.nuclei_version)
        except Exception as e:
            print(f"nuclei: unexpected error: {e}")
    if args.grype_version:
        try:
            install_grype(args.grype_version)
        except Exception as e:
            print(f"grype: unexpected error: {e}")
    if args.zap_version:
        try:
            install_zap(args.zap_version)
        except Exception as e:
            print(f"zap: unexpected error: {e}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
