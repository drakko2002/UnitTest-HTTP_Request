from fastapi import FastAPI, HTTPException, Security
from src.integrations.utils.get_token import get_token
from fastapi.security import HTTPBearer
import requests
from config import *
from sqlalchemy.orm import Session
from src.integrations.models.models import User, Organizations
from cryptography.fernet import Fernet
from jose import jwt, JWTError
import json

app = FastAPI()

security = HTTPBearer()

def get_github_orgs(HTTPAuthorizationCredentials = Security(security)):
    jwtToken = get_token(HTTPAuthorizationCredentials.credentials)
    if jwtToken == "":
        request_id = str(uuid.uuid4())
        raise HTTPException(status_code=400, detail=f"Todos os campos são obrigatórios. Request ID: {request_id}")

    cipher_suite = Fernet(ENCRIPTION_KEY)
    
    try:
        userTokenUid = jwtToken['id']
        db = SessionLocal()

        user = db.query(User).filter(User.uid == userTokenUid).first()
        userOrg = user.organizationid
        org = db.query(Organizations).filter(Organizations.id == userOrg).first()
        
        if user is None or org is None:
            db.close()
            raise HTTPException(status_code=404, detail="Usuário ou organização não encontrados.")

        encrypted_access_token = db.query(Organizations).filter(Organizations.id == userOrg).first().access_token

        if not encrypted_access_token and cipher_suite.decrypt(encrypted_access_token.encode()).decode().lower() == "null":
            raise HTTPException(status_code=400, detail="É necessário cadastrar todos os dados do Github primeiro.")
        
        else:
            github_access_token = cipher_suite.decrypt(org.access_token).decode()
            db.close()

            try:
                baseUrl = f"https://api.github.com/user/orgs"
                headers = {
                    "test_Content-Type": "application/json",
                    "Authorization": f"Bearer {github_access_token}"
                }
                response = requests.get(
                    baseUrl,
                    headers=headers
                )
                response.raise_for_status()

                github_orgs = response.json()

                return github_orgs
            except requests.RequestException as e:
                try:
                    error_details = e.response.json()
                    print(error_details)
                except ValueError:
                    print(e.response.text)
                raise HTTPException(status_code=400, detail="Erro na busca por workspaces.")

    except JWTError:
        raise HTTPException(status_code=400, detail="Token inválido.")
