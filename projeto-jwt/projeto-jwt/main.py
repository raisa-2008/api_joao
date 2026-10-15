import logging
import os
from datetime import datetime, timedelta, timezone

import jwt
from pwdlib import PasswordHash
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

logger = logging.getLogger("api_jwt")

app = FastAPI(title="API de Autenticação JWT")

# A chave deve ser configurada no ambiente, nunca publicada no código.
SECRET_KEY = os.getenv("JWT_SECRET")
if not SECRET_KEY:
    raise RuntimeError(
        "Configure a variável de ambiente JWT_SECRET antes de iniciar a API."
    )

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

password_hash = PasswordHash.recommended()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Usuários fictícios para fins didáticos.
# Em uma aplicação real, os usuários e hashes vêm de um banco de dados.
users_db = {
    "aluno": {
        "username": "aluno",
        "full_name": "Aluno de Teste",
        "hashed_password": password_hash.hash("senha123"),
    }
}


def authenticate_user(username: str, password: str):
    user = users_db.get(username)

    if not user:
        return None

    if not password_hash.verify(password, user["hashed_password"]):
        return None

    return user


def create_access_token(username: str):
    now = datetime.now(timezone.utc)

    payload = {
        "sub": username,
        "iat": now,
        "exp": now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    }

    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token



async def get_current_user(token: str = Depends(oauth2_scheme)):
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token inválido, expirado ou ausente.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
        )

        username = payload.get("sub")
        if not isinstance(username, str) or not username:
            raise unauthorized

    except InvalidTokenError:
        logger.warning("Falha de validação do JWT")
        raise unauthorized

    user = users_db.get(username)
    if user is None:
        raise unauthorized

    return user



@app.get("/")
def home():
    return {"mensagem": "API JWT funcionando!"}



@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(
        form_data.username,
        form_data.password,
    )

    if not user:
        logger.warning("Falha de login: credenciais inválidas")

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuário ou senha incorretos.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(user["username"])

    logger.info("Login bem-sucedido")

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    }



@app.get("/perfil")
def read_profile(current_user: dict = Depends(get_current_user)):
    logger.info("Acesso autorizado a GET /perfil")

    return {
        "mensagem": "Acesso autorizado!",
        "usuario": current_user["username"],
        "nome": current_user["full_name"],
    }
