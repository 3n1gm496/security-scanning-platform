import io
import tarfile

from orchestrator.scripts import fetch_binaries
from orchestrator.scripts.fetch_binaries import extract_tar_member


def test_extract_tar_member_writes_only_selected_file(tmp_path):
    archive_path = tmp_path / "tools.tar.gz"
    payload = b"binary-data"

    with tarfile.open(archive_path, "w:gz") as tf:
        info = tarfile.TarInfo("nested/nuclei")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))

    with tarfile.open(archive_path, "r:gz") as tf:
        member = next(member for member in tf.getmembers() if member.name == "nested/nuclei")
        extract_tar_member(tf, member, str(tmp_path / "nuclei"))

    assert (tmp_path / "nuclei").read_bytes() == payload
    assert not (tmp_path / "nested").exists()


def test_expected_sha256_from_release_uses_release_digest():
    release_json = {
        "assets": [
            {
                "name": "tool.tar.gz",
                "digest": "sha256:ABCDEF1234",
            }
        ]
    }

    assert fetch_binaries.expected_sha256_from_release(release_json, "tool.tar.gz") == "abcdef1234"


def test_expected_sha256_from_release_parses_checksum_asset(monkeypatch, tmp_path):
    checksum_file = tmp_path / "checksums.txt"
    checksum_file.write_text(
        "1111111111111111111111111111111111111111111111111111111111111111 other.tar.gz\n"
        "2222222222222222222222222222222222222222222222222222222222222222 tool.tar.gz\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(fetch_binaries, "DOWNLOAD_DIR", str(tmp_path))

    def fake_download(url, dst):
        assert url == "https://example.com/checksums.txt"
        with open(checksum_file, "rb") as src, open(dst, "wb") as out:
            out.write(src.read())
        return True

    monkeypatch.setattr(fetch_binaries, "download_url", fake_download)
    release_json = {
        "assets": [
            {"name": "tool.tar.gz"},
            {
                "name": "checksums.txt",
                "browser_download_url": "https://example.com/checksums.txt",
            },
        ]
    }

    assert (
        fetch_binaries.expected_sha256_from_release(release_json, "tool.tar.gz")
        == "2222222222222222222222222222222222222222222222222222222222222222"
    )
