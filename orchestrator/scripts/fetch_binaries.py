#!/usr/bin/env python3
"""Fetch release assets for nuclei, grype and zap and install them.
Best-effort helper used during Dockerfile build. Uses GitHub Releases API.
"""
import argparse
import json
import os
import shutil
import stat
import sys
import tarfile
import tempfile
import urllib.request
import zipfile

GITHUB_API = "https://api.github.com/repos/{owner}/{repo}/releases/tags/{tag}"
DOWNLOAD_DIR = "/tmp"


def download_url(url: str, dst: str) -> bool:
    try:
        with urllib.request.urlopen(url) as r, open(dst, "wb") as out:
            shutil.copyfileobj(r, out)
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
    try:
        with urllib.request.urlopen(url) as r:
            return json.load(r)
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
                    tf.extract(member, "/usr/local/bin")
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
                    tf.extract(member, "/usr/local/bin")
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
                zf.extractall("/opt")
        else:
            # assume tar.gz
            with tarfile.open(out, "r:gz") as tf:
                tf.extractall("/opt")
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
