from src.integrations.models.models import User

from fastapi import HTTPException, Security
from src.integrations.utils.get_token import get_token
from fastapi.security import HTTPBearer
from jose import jwt
import uuid
from config import *

security = HTTPBearer()

def authorize_git(HTTPAuthorizationCredentials = Security(security)):
    jwtToken = get_token(HTTPAuthorizationCredentials.credentials)
    if jwtToken == "":
        request_id = str(uuid.uuid4())
        print(f"Request ID UUIDv4: {request_id}")
        print("TOKEN VAZIO")
        raise HTTPException(status_code=400, detail=f"Todos os campos são obrigatórios. Request ID {request_id}")
    
    try:
        userTokenUid = jwtToken['id']
        db = SessionLocal()
        isUserAdmin = db.query(User).filter(User.uid == userTokenUid).first().isadm
        userOrg = db.query(User).filter(User.uid == userTokenUid).first().organizationid
        user_id = db.query(User).filter(User.uid == userTokenUid).first().id

        print(userTokenUid)
        db.close()
        return {
        "message": "Por favor, acesse a URL para autorizar o aplicativo",
        "authorize_url": f"{AUTHORIZE_URL}?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope=repo",
        "redirect_to_callback": True
    }
    except Exception as e:
        request_id = str(uuid.uuid4())
        print(e)
        raise HTTPException(status_code=400, detail=f"Erro ao gerar a URL de autorização. Request ID: {request_id}")