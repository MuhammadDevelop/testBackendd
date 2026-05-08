from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import EmailStr, BaseModel
from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv


load_dotenv()
api_key = os.getenv("SECRET_KEY")
algorithm = os.getenv("ALGORITHM")

ACCESS_TOKEN_EXPIRE_MINUTES = 30 

app = FastAPI()

origins = [
    "http://localhost.tiangolo.com",
    "https://127.0.0.1:5173",
    "http://localhost:5173",
    "http://localhost:8080",
    "http://127.0.0.1:5500/"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
user_db = []

class Register(BaseModel):
    username: str
    email: EmailStr
    password: str

class Login(BaseModel):
    email: EmailStr
    password: str

def get_password_hash(password):
    return pwd_context.hash(password)
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, api_key, algorithm=algorithm)

@app.post("/register")
def register_user(data: Register):
    for u in user_db:
        if u['email'] == data.email:
            raise HTTPException(status_code=400, detail="Bunday email allaqachon mavjud")
    
    hashed_password = get_password_hash(data.password)
    
    new_user = {
        "username": data.username,
        "email": data.email,
        "password": hashed_password 
    }
    user_db.append(new_user)
    return {"message": "Siz ro'yhatdan muvaffaqiyatli o'tdingiz"}

@app.post("/login")
def login(user: Login):
    db_user = next((u for u in user_db if u["email"] == user.email), None)
    
    if not db_user or not verify_password(user.password, db_user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email yoki parol xato",
        )
    
    access_token = create_access_token(data={"sub": db_user["email"]})
    return {"access_token": access_token, "token_type": "bearer"}