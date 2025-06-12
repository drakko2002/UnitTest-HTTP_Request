from src.integrations.models.models import (User, Organizations)
from fastapi import HTTPException
from fastapi.responses import RedirectResponse
import httpx
from cryptography.fernet import Fernet
from src.integrations.utils.get_user_info_localstorage import get_user_info_from_localstorage
from config import *

async def fetch_access_token(code: str) -> str:
    """Obtém o token de acesso do GitHub"""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                TOKEN_URL,
                data={
                    "client_id": CLIENT_ID,
                    "client_secret": CLIENT_SECRET,
                    "code": code,
                    "redirect_uri": REDIRECT_URI,
                },
                headers={"Accept": "application/json"},
            )
            response.raise_for_status()
            return response.json()["access_token"]
    except httpx.HTTPError as e:
        raise HTTPException(status_code=e.status_code, detail=f"Erro ao obter token de acesso: {e}")

def initialize_cipher() -> Fernet:
    """Inicializa o objeto de criptografia"""
    try:
        return Fernet(ENCRIPTION_KEY)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao inicializar criptografia: {e}")

async def get_user_organizations(access_token: str) -> list:
    """Obtém as organizações do usuário"""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://api.github.com/user/orgs",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            response.raise_for_status()
            return response.json()
    except httpx.HTTPError as e:
        raise HTTPException(status_code=e.status_code, detail=f"Erro ao obter organizações: {e}")

async def callback_git(code: str, token: str):
    """Callback do GitHub"""
    try:
        access_token = await fetch_access_token(code)
        cipher_suite = initialize_cipher()
        orgs = await get_user_organizations(access_token)
        if not orgs:
            raise HTTPException(status_code=404, detail="Usuário não pertence a nenhuma organização.")
        org_name = orgs[0]["login"]
        user_info = get_user_info_from_localstorage(token)
        userTokenUid = user_info["id"]
        db = SessionLocal()
        user = db.query(User).filter(User.uid == userTokenUid).first()
        if user is None:
            raise HTTPException(status_code=404, detail="Usuário não encontrado.")
        isUserAdmin = user.isadm
        userOrg = user.organizationid
        user_id = user.id
        orgUUID = db.query(Organizations).filter(Organizations.id == userOrg).first().uuid
        encrypted_token = cipher_suite.encrypt(access_token.encode())
        if isUserAdmin and userOrg and user_id and orgUUID:
            db.query(Organizations).filter(Organizations.id == userOrg).update(
                {"access_token": encrypted_token, "git_attach": True}
            )
            db.commit()
            db.close()
        else:
            raise HTTPException(status_code=400, detail="Campos necessários não estão preenchidos corretamente.")
        # Construa a URL da API usando o nome da organização
        API_URL_ORG = f"https://api.github.com/orgs/{org_name}/repos"
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao processar callback: {e}")