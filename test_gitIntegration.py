# tests/test_github_oauth.py

import pytest
import httpx
import responses
import respx
from httpx import Response as HxResponse
from fastapi import HTTPException

# importe suas funções
from test_Content.callback_git import fetch_access_token, get_user_organizations
from test_Content.get_github_branches import get_github_repo_branches
from test_Content.get_github_orgs import get_github_orgs

# ================================
# 1) Testes assíncronos (httpx)
# ================================
@pytest.mark.asyncio
@respx.mock
async def test_fetch_access_token_success():
    code = "fake_code"
    url = "https://github.com/login/oauth/access_token"
    # mock do HTTPX POST
    respx.post(url).respond(
        200,
        json={"access_token": "tokentest", "token_type": "bearer"}
    )

    token = await fetch_access_token(code)
    assert token == "tokentest"


@pytest.mark.asyncio
@respx.mock
async def test_fetch_access_token_http_error():
    code = "bad"
    url = "https://github.com/login/oauth/access_token"
    respx.post(url).respond(400, json={"error": "bad_verification_code"})

    with pytest.raises(HTTPException) as exc:
        await fetch_access_token(code)
    assert "Erro ao obter token" in exc.value.detail


@pytest.mark.asyncio
@respx.mock
async def test_get_user_organizations_success():
    token = "tokentest"
    url = "https://api.github.com/user/orgs"
    dummy = [{"login": "org1"}, {"login": "org2"}]
    respx.get(url).respond(200, json=dummy)

    orgs = await get_user_organizations(token)
    assert orgs == dummy


@pytest.mark.asyncio
@respx.mock
async def test_get_user_organizations_fail():
    token = "tokentest"
    url = "https://api.github.com/user/orgs"
    respx.get(url).respond(404, json={"message": "Not Found"})

    with pytest.raises(HTTPException):
        await get_user_organizations(token)


# ========================================
# 2) Testes síncronos (requests + responses)
# ========================================
@responses.activate
def test_get_github_orgs_success(monkeypatch):
    # monkeypatch do get_token para não depender do JWT
    monkeypatch.setattr(
        "src.integrations.get_github_orgs.get_token",
        lambda cred: {"id": 1}
    )
    # monkeypatch do DB + organização
    class DummyOrg:
        access_token = "encrypted"
    from cryptography.fernet import Fernet
    # fake decrypt: retorna um token simples
    monkeypatch.setattr(Fernet, "decrypt", lambda self, x: b"tokentest")

    # simula consulta de orgs no GitHub
    orgs_url = "https://api.github.com/user/orgs"
    responses.add(
        responses.GET,
        orgs_url,
        json=[{"login": "meu-org"}],
        status=200
    )

    creds = type("C", (), {"credentials": "fake_jwt"})
    result = get_github_orgs(creds)
    assert isinstance(result, list)
    assert result[0]["login"] == "meu-org"


@responses.activate
def test_get_github_repo_branches_success(monkeypatch):
    monkeypatch.setattr(
        "src.integrations.get_github_branches.get_token",
        lambda cred: {"id": 1}
    )
    from cryptography.fernet import Fernet
    monkeypatch.setattr(Fernet, "decrypt", lambda self, x: b"tokentest")

    branches_url = "https://api.github.com/repos/org1/repo1/branches"
    responses.add(
        responses.GET,
        branches_url,
        json=[{"name": "main"}, {"name": "dev"}],
        status=200
    )

    creds = type("C", (), {"credentials": "fake_jwt"})
    branches = get_github_repo_branches("org1", "repo1", creds)
    assert len(branches) == 2
    assert branches[0]["name"] == "main"


@responses.activate
def test_get_github_orgs_missing_token(monkeypatch):
    # get_token retorna string vazia para forçar erro
    monkeypatch.setattr(
        "src.integrations.get_github_orgs.get_token",
        lambda cred: ""
    )
    creds = type("C", (), {"credentials": "fake"})
    with pytest.raises(HTTPException):
        get_github_orgs(creds)

