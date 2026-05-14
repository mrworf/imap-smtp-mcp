from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_docker_publish_job_is_gated_after_quality_gates() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    assert "quality-gates:" in workflow
    assert "actions/setup-python@v6" in workflow
    assert "actions/setup-python@v5" not in workflow
    assert "docker-image:" in workflow
    assert "needs: quality-gates" in workflow
    assert "github.event_name == 'push' && github.ref == 'refs/heads/main'" in workflow
    assert "pytest -q" in workflow


def test_docker_publish_uses_ghcr_and_github_token() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    assert "REGISTRY: ghcr.io" in workflow
    assert "IMAGE_NAME: imap-smtp-mcp" in workflow
    assert "registry: ${{ env.REGISTRY }}" in workflow
    assert "username: ${{ github.actor }}" in workflow
    assert "password: ${{ secrets.GITHUB_TOKEN }}" in workflow
    assert "${{ env.REGISTRY }}/${{ github.repository_owner }}/${{ env.IMAGE_NAME }}" in workflow
    assert "DOCKERHUB" not in workflow.upper()


def test_docker_publish_keeps_relevant_change_filtering() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    assert "dorny/paths-filter@v3" in workflow
    assert "id: changed" in workflow
    assert "steps.changed.outputs.docker == 'true'" in workflow
    assert "'Dockerfile'" in workflow
    assert "'src/**'" in workflow
