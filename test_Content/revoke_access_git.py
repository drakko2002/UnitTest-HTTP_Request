from src.integrations.models.models import (User,Organizations)
from fastapi import HTTPException, Security
from src.integrations.utils.get_token import get_token
from fastapi.security import HTTPBearer
from jose import jwt
import uuid
from config import *

security = HTTPBearer()

def revoke_git(HTTPAuthorizationCredentials = Security(security)):
    jwtToken = get_token(HTTPAuthorizationCredentials.credentials)
    
    
    cargo_id = jwtToken.get('cargo_id', 4)
    
    if jwtToken == "":
        request_id = str(uuid.uuid4())
        print(f"Request ID UUIDv4: {request_id}")
        raise HTTPException(status_code=403, detail=f"Todos os campos são obrigatórios. Request ID: {request_id}")
    
    userTokenUid = jwtToken['id']
    db = SessionLocal()


    if cargo_id in (4, 5, 6):
        request_id = str(uuid.uuid4())
        print(f"Request ID UUIDv4: {request_id}")
        raise HTTPException(status_code=403, detail=f"Você não tem permissão para realizar esta ação. Request ID: {request_id}")
    
    userAdminOrg = db.query(User).filter(User.uid == userTokenUid).first().organizationid
    
    org = db.query(Organizations).filter(Organizations.id == userAdminOrg).first()

    if org is None:
        request_id = str(uuid.uuid4())
        print(f"Request ID UUIDv4: {request_id}")
        raise HTTPException(status_code=403, detail=f"Você não tem permissão para realizar esta ação. Request ID: {request_id}")
    
    if org.id != userAdminOrg:
        request_id = str(uuid.uuid4())
        print(f"Request ID UUIDv4: {request_id}")
        raise HTTPException(status_code=403, detail=f"Você não tem permissão para realizar esta ação. Request ID: {request_id}")
    
    org.access_token = None
    db.commit()
    db.close()
    return {"Token de acesso Git removido com sucesso."}
