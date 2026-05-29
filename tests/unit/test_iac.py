"""IaC misconfiguration analyzer (Dockerfile / docker-compose / Terraform)."""

from __future__ import annotations

from orthrus.iac import analyze_compose, analyze_dockerfile, analyze_path, analyze_terraform


def _titles(findings) -> str:
    return " | ".join(f.title for f in findings)


# ----------------------------------------------------------------- Dockerfile
def test_dockerfile_flags_root_latest_secret_and_pipe() -> None:
    df = (
        "FROM ubuntu:latest\n"
        "ENV API_KEY=sk-live-abc123\n"
        "RUN curl https://get.example.sh | sh\n"
        "ADD https://example.com/x.tar /x\n"
        "CMD [\"./run\"]\n"
    )
    titles = _titles(analyze_dockerfile(df))
    assert "Unpinned base image" in titles
    assert "Hardcoded secret" in titles
    assert "Remote script piped" in titles
    assert "ADD from a remote URL" in titles
    assert "runs as root" in titles  # no USER


def test_dockerfile_clean_is_quiet() -> None:
    df = "FROM ubuntu:22.04@sha256:abcd\nRUN apt-get update\nUSER appuser\nCMD [\"./run\"]\n"
    titles = _titles(analyze_dockerfile(df))
    assert "runs as root" not in titles
    assert "Unpinned base image" not in titles
    assert "Hardcoded secret" not in titles


def test_dockerfile_secret_reference_not_flagged() -> None:
    # A reference (file path / $VAR), not a literal secret -> no finding.
    df = "FROM x:1@sha256:y\nUSER app\nENV SECRET_FILE=/run/secrets/db\nARG TOKEN=${BUILD_TOKEN}\n"
    assert "Hardcoded secret" not in _titles(analyze_dockerfile(df))


# ----------------------------------------------------------------- compose
def test_compose_flags_privileged_socket_and_secret() -> None:
    yml = (
        "services:\n"
        "  web:\n"
        "    image: nginx:latest\n"
        "    privileged: true\n"
        "    volumes:\n"
        "      - /var/run/docker.sock:/var/run/docker.sock\n"
        "    environment:\n"
        "      DB_PASSWORD: hunter2\n"
    )
    titles = _titles(analyze_compose(yml))
    assert "Privileged container" in titles
    assert "Docker socket mounted" in titles
    assert "Hardcoded secret" in titles
    assert "Unpinned image" in titles


def test_compose_clean_and_bad_yaml() -> None:
    yml = "services:\n  web:\n    image: nginx:1.27.0@sha256:abc\n    environment:\n      DEBUG: 'false'\n"
    assert analyze_compose(yml) == []
    assert analyze_compose("::: not yaml :::") == []


# ----------------------------------------------------------------- terraform
def test_terraform_flags_open_sg_public_acl_unencrypted_secret() -> None:
    tf = (
        'resource "aws_security_group" "x" {\n'
        "  ingress { cidr_blocks = [\"0.0.0.0/0\"] }\n"
        "}\n"
        'resource "aws_s3_bucket" "b" { acl = "public-read" }\n'
        'resource "aws_ebs_volume" "v" { encrypted = false }\n'
        'resource "aws_db_instance" "d" { password = "supersecret123" }\n'
    )
    titles = _titles(analyze_terraform(tf))
    assert "open to the internet" in titles
    assert "Public storage ACL" in titles
    assert "Encryption at rest disabled" in titles
    assert "Hardcoded secret" in titles


def test_terraform_var_reference_not_flagged() -> None:
    tf = 'resource "x" "y" { password = var.db_password }\n'
    assert "Hardcoded secret" not in _titles(analyze_terraform(tf))


# ----------------------------------------------------------------- walk a tree
def test_analyze_path_walks_directory(tmp_path) -> None:
    (tmp_path / "Dockerfile").write_text("FROM alpine:latest\nRUN echo hi\n", encoding="utf-8")
    (tmp_path / "main.tf").write_text('x { cidr_blocks = ["0.0.0.0/0"] }\n', encoding="utf-8")
    sub = tmp_path / ".git"
    sub.mkdir()
    (sub / "Dockerfile").write_text("FROM x:latest\n", encoding="utf-8")  # must be skipped
    findings = analyze_path(str(tmp_path))
    assert any("Dockerfile" in f.url for f in findings)
    assert any("main.tf" in f.url for f in findings)
    assert all(".git" not in f.url for f in findings)  # skipped dir
