from src.integrations.models.models import User, Organizations
from fastapi import HTTPException, Security
from src.integrations.utils.get_token import get_token
from fastapi.security import HTTPBearer
from cryptography.fernet import Fernet
from config import *
from jose import jwt
import uuid

security = HTTPBearer()

def get_token_git(HTTPAuthorizationCredentials = Security(security)):
    # Leitura da chave de criptografia
    cipher_suite = Fernet(ENCRIPTION_KEY)
    jwtToken = get_token(HTTPAuthorizationCredentials.credentials)
    
    if jwtToken == "":
        request_id = str(uuid.uuid4())
        raise HTTPException(status_code=400, detail=f"Todos os campos são obrigatórios. Request ID: {request_id}")
    
    userTokenUid = jwtToken['id']
    db = SessionLocal()
    
    try:
        user = db.query(User).filter(User.uid == userTokenUid).first()
        if not user:
            raise HTTPException(status_code=404, detail="Usuário não encontrado")
            
        isUserAdmin = user.isadm
        userOrgID = user.organizationid
        userUUID = user.uid
        
        org = db.query(Organizations).filter(Organizations.id == userOrgID).first()
        if not org:
            raise HTTPException(status_code=404, detail="Organização não encontrada")
            
        orgUUID = org.uuid
        encrypted_access_token = org.access_token
        
        # Verificar se o token existe e não é nulo
        if encrypted_access_token is None:
            raise HTTPException(status_code=400, detail="GitHub não integrado")
        
        try:
            decrypted_token = cipher_suite.decrypt(encrypted_access_token.encode()).decode()
            if decrypted_token.lower() == "null":
                return {"status": "not_integrated", "message": "GitHub não integrado"}
            
            # Token válido encontrado
            return {"status": "integrated", "message": "GitHub já integrado", "token": decrypted_token}
            
        except Exception as e:
            request_id = str(uuid.uuid4())
            raise HTTPException(status_code=400, detail=f"Erro na descriptografia: {e} Request ID: {request_id}")
    
    except HTTPException:
        raise
    except Exception as e:
        request_id = str(uuid.uuid4())
        raise HTTPException(status_code=500, detail=f"Erro ao processar requisição: {str(e)} Request ID: {request_id}")
    finally:
        db.close()