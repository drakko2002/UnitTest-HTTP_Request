from fastapi import FastAPI, HTTPException, Security
from src.integrations.utils.get_token import get_token
from fastapi.security import HTTPBearer
import requests
from config import *
from sqlalchemy.orm import Session
from src.integrations.models.models import User, Organizations, BitbucketBranch
from cryptography.fernet import Fernet
from jose import jwt, JWTError
import json

app = FastAPI()
security = HTTPBearer()

def get_github_repo_branches(orgName: str, repoName: str, HTTPAuthorizationCredentials = Security(security)):
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
        github_org = orgName
        github_repo = repoName

        if not encrypted_access_token and cipher_suite.decrypt(encrypted_access_token.encode()).decode().lower() == "null":
            raise HTTPException(status_code=400, detail="É necessário cadastrar todos os dados do Github primeiro.")
        
        elif not github_org or not github_repo:
            raise HTTPException(status_code=400, detail="É necessário informar a organização e o repositório.")
        else:
            github_access_token = cipher_suite.decrypt(org.access_token).decode()
            db.close()

            try:
                baseUrl = f"https://api.github.com/repos/{github_org}/{github_repo}/branches"
                headers = {
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {github_access_token}"
                }
                response = requests.get(
                    baseUrl,
                    headers=headers
                )
                response.raise_for_status()
                branches_data = response.json()
    
                return branches_data
            except requests.RequestException as e:
                try:
                    error_details = e.response.json()
                    print(error_details)
                except ValueError:
                    print(e.response.text)
                raise HTTPException(status_code=400, detail="Erro na busca por repositórios.")

    except JWTError:
        raise HTTPException(status_code=400, detail="Token inválido.")
