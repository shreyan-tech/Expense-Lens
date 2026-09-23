import os
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
import jwt

from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, ForeignKey, Text
from sqlalchemy.orm import declarative_base, sessionmaker, Session

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./test.db")
SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey12345")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    currency = Column(String, default="INR")
    created_at = Column(DateTime, default=datetime.utcnow)

class Transaction(Base):
    __tablename__ = "transactions"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    type = Column(String, nullable=False)
    amount = Column(Float, nullable=False)
    merchant = Column(String, nullable=False)
    description = Column(Text, default="")
    category = Column(String, nullable=False)
    account = Column(String, default="Primary")
    payment_method = Column(String, default="UPI")
    transaction_date = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

app = FastAPI(title="ExpenseLens API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login")

class RegisterSchema(BaseModel):
    name: str
    email: EmailStr
    password: str

class LoginSchema(BaseModel):
    email: EmailStr
    password: str

class TransactionCreate(BaseModel):
    type: str
    amount: float
    merchant: str
    description: Optional[str] = ""
    category: str
    account: Optional[str] = "Primary"
    payment_method: Optional[str] = "UPI"
    transaction_date: Optional[datetime] = None

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def authenticate_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid auth token")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid auth credentials")
    
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@app.get("/health")
def health():
    return {"status": "ok", "app": "ExpenseLens API"}

@app.post("/api/auth/register")
def register(data: RegisterSchema, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == data.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email is already registered")
    
    user = User(
        name=data.name,
        email=data.email,
        password_hash=pwd_context.hash(data.password)
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    token = create_access_token({"sub": user.email, "id": user.id})
    return {"token": token, "user": {"id": user.id, "name": user.name, "email": user.email, "currency": user.currency}}

@app.post("/api/auth/login")
def login(data: LoginSchema, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email).first()
    if not user or not pwd_context.verify(data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    
    token = create_access_token({"sub": user.email, "id": user.id})
    return {"token": token, "user": {"id": user.id, "name": user.name, "email": user.email, "currency": user.currency}}

@app.get("/api/transactions")
def get_transactions(user: User = Depends(authenticate_user), db: Session = Depends(get_db)):
    return db.query(Transaction).filter(Transaction.user_id == user.id).order_by(Transaction.transaction_date.desc()).all()

@app.post("/api/transactions")
def create_transaction(data: TransactionCreate, user: User = Depends(authenticate_user), db: Session = Depends(get_db)):
    txn = Transaction(
        user_id=user.id,
        type=data.type,
        amount=data.amount,
        merchant=data.merchant,
        description=data.description or "",
        category=data.category,
        account=data.account,
        payment_method=data.payment_method,
        transaction_date=data.transaction_date or datetime.utcnow()
    )
    db.add(txn)
    db.commit()
    db.refresh(txn)
    return txn

@app.delete("/api/transactions/{txn_id}")
def delete_transaction(txn_id: int, user: User = Depends(authenticate_user), db: Session = Depends(get_db)):
    txn = db.query(Transaction).filter(Transaction.id == txn_id, Transaction.user_id == user.id).first()
    if not txn:
        raise HTTPException(status_code=404, detail="Transaction not found")
    db.delete(txn)
    db.commit()
    return {"success": True}
