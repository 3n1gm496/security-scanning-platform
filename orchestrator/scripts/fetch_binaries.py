#!/usr/bin/env python3
"""Fetch release assets for nuclei, grype and zap and install them.
Best-effort helper used during Dockerfile build. Uses GitHub Releases API.
"""

import argparse
import hashlib
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path
from urllib.parse import urlparse

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


def extract_tar_member(archive: tarfile.TarFile, member: tarfile.TarInfo, destination: str) -> None:
    """Extract a single regular-file member to a specific destination path."""
    if not member.isfile():
        raise ValueError(f"refusing to extract non-file member: {member.name}")
    os.makedirs(os.path.dirname(destination), exist_ok=True)
    src = archive.extractfile(member)
    if src is None:
        raise ValueError(f"unable to read archive member: {member.name}")
    with src, open(destination, "wb") as dst:
        shutil.copyfileobj(src, dst)


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


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def pick_asset(release_json: dict, name_contains: tuple[str, ...]) -> dict | None:
    for asset in release_json.get("assets", []):
        name = asset.get("name", "")
        lname = name.lower()
        if all(part in lname for part in name_contains):
            return asset
    return None


def find_checksum_asset(release_json: dict) -> dict | None:
    candidates = []
    for asset in release_json.get("assets", []):
        name = asset.get("name", "").lower()
        if ("checksum" in name or "sha256" in name) and not name.endswith((".txt.asc", ".txt.sig", ".sig", ".asc")):
            candidates.append(asset)
    for asset in candidates:
        if asset.get("name", "").lower().endswith(".txt"):
            return asset
    return candidates[0] if candidates else None


def expected_sha256_from_release(release_json: dict, asset_name: str) -> str | None:
    for asset in release_json.get("assets", []):
        if asset.get("name") != asset_name:
            continue
        digest = asset.get("digest", "")
        if isinstance(digest, str) and digest.startswith("sha256:"):
            return digest.split(":", 1)[1].strip().lower()

    checksum_asset = find_checksum_asset(release_json)
    if not checksum_asset:
        return None

    fd, checksum_path = tempfile.mkstemp(
        prefix="fetch-binaries-checksum-",
        suffix=f"-{os.path.basename(checksum_asset['name'])}",
        dir=DOWNLOAD_DIR,
    )
    os.close(fd)

    try:
        if not download_url(checksum_asset["browser_download_url"], checksum_path):
            return None
        with open(checksum_path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line or asset_name not in line:
                    continue
                parts = line.replace("  ", " ").split()
                if len(parts) >= 2 and parts[-1].endswith(asset_name):
                    return parts[0].lower()
        return None
    finally:
        if os.path.exists(checksum_path):
            os.remove(checksum_path)


def verify_download(release_json: dict, asset: dict, downloaded_path: str) -> bool:
    expected = expected_sha256_from_release(release_json, asset["name"])
    if not expected:
        print(f"{asset['name']}: checksum metadata not found in release, refusing install")
        return False
    actual = sha256_file(downloaded_path)
    if actual != expected:
        print(f"{asset['name']}: checksum mismatch expected={expected} actual={actual}")
        return False
    print(f"{asset['name']}: checksum verified")
    return True


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
        # Make scanner binaries executable for non-root runtime users too
        # (e.g. scanuser in Docker images).
        os.chmod(
            path,
            st.st_mode | stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH,
        )
    except Exception:
        pass


def install_nuclei(version: str) -> None:
    # nuclei releases vary in naming; try several heuristics
    tag = f"v{version}"
    rel = get_release("projectdiscovery", "nuclei", tag)
    if not rel:
        print("nuclei: release metadata not found, skipping")
        return
    # prefer linux amd64 zip, then tar.gz
    asset = (
        pick_asset(rel, ("linux", "amd64", ".zip"))
        or pick_asset(rel, ("linux", "amd64", ".tar.gz"))
        or pick_asset(rel, ("linux", "64", ".zip"))
        or pick_asset(rel, ("linux", "64", ".tar.gz"))
    )
    if not asset:
        print("nuclei: no suitable asset found in release, skipping")
        return
    out = os.path.join(DOWNLOAD_DIR, os.path.basename(asset["browser_download_url"]))
    print(f"nuclei: downloading {asset['browser_download_url']} -> {out}")
    if not download_url(asset["browser_download_url"], out):
        print("nuclei: download failed")
        return
    if not verify_download(rel, asset, out):
        return
    try:
        dst = "/usr/local/bin/nuclei"
        if out.endswith(".zip"):
            with zipfile.ZipFile(out, "r") as zf:
                for member in zf.namelist():
                    if os.path.basename(member) != "nuclei" or member.endswith("/"):
                        continue
                    with zf.open(member) as src, open(dst, "wb") as dst_file:
                        shutil.copyfileobj(src, dst_file)
                    ensure_executable(dst)
                    print("nuclei: installed to /usr/local/bin/nuclei")
                    break
        else:
            with tarfile.open(out, "r:gz") as tf:
                for member in tf.getmembers():
                    if os.path.basename(member.name) == "nuclei":
                        extract_tar_member(tf, member, dst)
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
    asset = (
        pick_asset(rel, (version.lower(), "linux", "amd64", ".tar.gz"))
        or pick_asset(rel, ("linux", "amd64", ".tar.gz"))
        or pick_asset(rel, ("linux", "64", ".tar.gz"))
        or pick_asset(rel, (version.lower(), "linux", "amd64", ".deb"))
        or pick_asset(rel, ("linux", "amd64", ".deb"))
        or pick_asset(rel, ("linux", "64", ".deb"))
    )
    if not asset:
        print("grype: no suitable asset found in release, skipping")
        return
    out = os.path.join(DOWNLOAD_DIR, os.path.basename(asset["browser_download_url"]))
    print(f"grype: downloading {asset['browser_download_url']} -> {out}")
    if not download_url(asset["browser_download_url"], out):
        print("grype: download failed")
        return
    if not verify_download(rel, asset, out):
        return
    try:
        dst = "/usr/local/bin/grype"
        if out.endswith(".deb"):
            with tempfile.TemporaryDirectory(prefix="grype-deb-") as tmpdir:
                subprocess.run(["dpkg-deb", "-x", out, tmpdir], check=True)
                candidate = os.path.join(tmpdir, "usr", "bin", "grype")
                if not os.path.exists(candidate):
                    raise FileNotFoundError("grype binary not found in .deb package")
                shutil.copy(candidate, dst)
                ensure_executable(dst)
                print("grype: installed to /usr/local/bin/grype")
        else:
            with tarfile.open(out, "r:gz") as tf:
                for member in tf.getmembers():
                    if os.path.basename(member.name) == "grype":
                        extract_tar_member(tf, member, dst)
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
    asset = pick_asset(rel, ("linux", ".tar.gz")) or pick_asset(rel, ("linux", ".zip"))
    if not asset:
        print("zap: no suitable linux asset found in release, skipping")
        return
    basename = os.path.basename(asset["browser_download_url"])
    out = os.path.join(DOWNLOAD_DIR, basename)
    print(f"zap: downloading {asset['browser_download_url']} -> {out}")
    if not download_url(asset["browser_download_url"], out):
        print("zap: download failed")
        return
    if not verify_download(rel, asset, out):
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


def install_trivy(version: str) -> None:
    tag = f"v{version}"
    rel = get_release("aquasecurity", "trivy", tag)
    if not rel:
        print("trivy: release metadata not found, skipping")
        return
    asset = pick_asset(rel, (version.lower(), "linux-64bit", ".tar.gz"))
    if not asset:
        print("trivy: no suitable asset found in release, skipping")
        return
    out = os.path.join(DOWNLOAD_DIR, "trivy.tar.gz")
    print(f"trivy: downloading {asset['browser_download_url']} -> {out}")
    if not download_url(asset["browser_download_url"], out):
        print("trivy: download failed")
        return
    if not verify_download(rel, asset, out):
        return
    with tarfile.open(out, "r:gz") as tf:
        for member in tf.getmembers():
            if os.path.basename(member.name) == "trivy":
                extract_tar_member(tf, member, "/usr/local/bin/trivy")
                ensure_executable("/usr/local/bin/trivy")
                print("trivy: installed to /usr/local/bin/trivy")
                break


def install_gitleaks(version: str) -> None:
    tag = f"v{version}"
    rel = get_release("gitleaks", "gitleaks", tag)
    if not rel:
        print("gitleaks: release metadata not found, skipping")
        return
    asset = pick_asset(rel, (version.lower(), "linux", "x64", ".tar.gz"))
    if not asset:
        print("gitleaks: no suitable asset found in release, skipping")
        return
    out = os.path.join(DOWNLOAD_DIR, "gitleaks.tar.gz")
    print(f"gitleaks: downloading {asset['browser_download_url']} -> {out}")
    if not download_url(asset["browser_download_url"], out):
        print("gitleaks: download failed")
        return
    if not verify_download(rel, asset, out):
        return
    with tarfile.open(out, "r:gz") as tf:
        for member in tf.getmembers():
            if os.path.basename(member.name) == "gitleaks":
                extract_tar_member(tf, member, "/usr/local/bin/gitleaks")
                ensure_executable("/usr/local/bin/gitleaks")
                print("gitleaks: installed to /usr/local/bin/gitleaks")
                break


def install_syft(version: str) -> None:
    tag = f"v{version}"
    rel = get_release("anchore", "syft", tag)
    if not rel:
        print("syft: release metadata not found, skipping")
        return
    asset = pick_asset(rel, (version.lower(), "linux", "amd64", ".tar.gz"))
    if not asset:
        print("syft: no suitable asset found in release, skipping")
        return
    out = os.path.join(DOWNLOAD_DIR, "syft.tar.gz")
    print(f"syft: downloading {asset['browser_download_url']} -> {out}")
    if not download_url(asset["browser_download_url"], out):
        print("syft: download failed")
        return
    if not verify_download(rel, asset, out):
        return
    with tarfile.open(out, "r:gz") as tf:
        for member in tf.getmembers():
            if os.path.basename(member.name) == "syft":
                extract_tar_member(tf, member, "/usr/local/bin/syft")
                ensure_executable("/usr/local/bin/syft")
                print("syft: installed to /usr/local/bin/syft")
                break


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trivy-version", default="", help="trivy release version (no v prefix)")
    parser.add_argument("--gitleaks-version", default="", help="gitleaks release version (no v prefix)")
    parser.add_argument("--syft-version", default="", help="syft release version (no v prefix)")
    parser.add_argument("--nuclei-version", default="", help="nuclei release version (no v prefix)")
    parser.add_argument("--grype-version", default="", help="grype release version (no v prefix)")
    parser.add_argument("--zap-version", default="", help="zap release version (no v prefix)")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("fetch_binaries: must run as root to install into /usr/local/bin and /opt")
        return 1

    if args.trivy_version:
        try:
            install_trivy(args.trivy_version)
        except Exception as e:
            print(f"trivy: unexpected error: {e}")
    if args.gitleaks_version:
        try:
            install_gitleaks(args.gitleaks_version)
        except Exception as e:
            print(f"gitleaks: unexpected error: {e}")
    if args.syft_version:
        try:
            install_syft(args.syft_version)
        except Exception as e:
            print(f"syft: unexpected error: {e}")
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
