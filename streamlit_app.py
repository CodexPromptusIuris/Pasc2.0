# streamlit_app.py
"""PASC PRO - Streamlit Frontend (single-file)
- Uses SQLAlchemy DB (same models as Flask backend) via direct calls
- Email token (itsdangerous) + TOTP (pyotp) support
- Audit JSONL HMAC logging
- Designed to run behind reverse proxy (HTTPS)
"""
import os, json, hmac, hashlib
from datetime import datetime, timedelta
from pathlib import Path
import streamlit as st
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import pyotp
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from flask_mail import Mail, Message  # using Flask-Mail for SMTP convenience

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / 'instance'
INSTANCE_DIR.mkdir(exist_ok=True)

# env vars
SECRET_KEY = os.environ.get('PASC_SECRET_KEY')
if not SECRET_KEY:
    raise RuntimeError('PASC_SECRET_KEY required')
HMAC_KEY = os.environ.get('PASC_HMAC_KEY') or SECRET_KEY
DATABASE_URL = os.environ.get('DATABASE_URL') or f"sqlite:///{INSTANCE_DIR/'pasc_streamlit.db'}"

MAIL_SERVER = os.environ.get('MAIL_SERVER', 'localhost')
MAIL_PORT = int(os.environ.get('MAIL_PORT', 25))
MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'false').lower() in ('1','true')
MAIL_USE_SSL = os.environ.get('MAIL_USE_SSL', 'false').lower() in ('1','true')
MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', 'no-reply@pasc.example')

URL_SIGNER = URLSafeTimedSerializer(SECRET_KEY)
AUDIT_FILE = INSTANCE_DIR / 'pasc_audit_log_streamlit.jsonl'

# DB setup (SQLAlchemy)
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

class UserModel(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    totp_secret = Column(String(64), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

# Flask-Mail config (we use Mail object purely to send emails via SMTP)
from flask import Flask
app = Flask(__name__)
app.config.update(
    MAIL_SERVER=MAIL_SERVER,
    MAIL_PORT=MAIL_PORT,
    MAIL_USERNAME=MAIL_USERNAME,
    MAIL_PASSWORD=MAIL_PASSWORD,
    MAIL_USE_TLS=MAIL_USE_TLS,
    MAIL_USE_SSL=MAIL_USE_SSL,
    MAIL_DEFAULT_SENDER=MAIL_DEFAULT_SENDER,
)
mail = Mail(app)

def sign_record(record: str) -> str:
    return hmac.new(HMAC_KEY.encode(), record.encode(), hashlib.sha256).hexdigest()

def audit(event: str, details: dict):
    record = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'event': event,
        'details': details,
    }
    line = json.dumps(record, ensure_ascii=False)
    signature = sign_record(line)
    with open(AUDIT_FILE, 'a', encoding='utf-8') as f:
        f.write(json.dumps({'record': record, 'hmac': signature}, ensure_ascii=False) + '\n')

def generate_email_token(email: str):
    return URL_SIGNER.dumps({'email': email, 'purpose': 'login'})

def verify_email_token(token: str, max_age=600):
    try:
        data = URL_SIGNER.loads(token, max_age=max_age)
        return data
    except (BadSignature, SignatureExpired):
        return None

def send_email_token(email: str, token: str):
    # uses Flask-Mail under app context
    with app.app_context():
        msg = Message(subject='Tu código de acceso PASC PRO', recipients=[email])
        msg.body = f"Usa este token para acceder (válido por unos minutos): {token}"
        mail.send(msg)

# Streamlit UI
st.set_page_config(page_title='PASC PRO', layout='centered')
st.title('PASC PRO - Acceso Seguro (Streamlit)')
session_state = st.session_state

if 'email' not in session_state:
    session_state['email'] = ''
if 'pending_token' not in session_state:
    session_state['pending_token'] = ''
if 'authenticated' not in session_state:
    session_state['authenticated'] = False

if session_state['authenticated']:
    st.success(f"Conectado como {session_state['email']}")
    if st.button('Cerrar sesión'):
        audit('logout', {'email': session_state['email']})
        session_state['authenticated'] = False
        session_state['email'] = ''
        session_state['pending_token'] = ''
    st.stop()

# Step 1: Request access
with st.form('request_form'):
    email = st.text_input('Correo corporativo', value=session_state['email'])
    submit = st.form_submit_button('Solicitar acceso')
if submit:
    email = email.strip().lower()
    # save to DB if not exists
    db = SessionLocal()
    user = db.query(UserModel).filter_by(email=email).first()
    if not user:
        user = UserModel(email=email, totp_secret=pyotp.random_base32())
        db.add(user)
        db.commit()
    token = generate_email_token(email)
    try:
        send_email_token(email, token)
        audit('request_access', {'email': email})
        st.info('Se ha enviado un código a tu correo')
        session_state['email'] = email
        session_state['pending_token'] = token
    except Exception as e:
        st.error('Error enviando el correo. Revisa configuración SMTP.')
    db.close()

# Step 2: Verify token or TOTP
st.markdown('---')
with st.form('verify_form'):
    token_in = st.text_input('Ingresa el código (o token)')
    verify = st.form_submit_button('Verificar')
if verify:
    token_in = token_in.strip()
    db = SessionLocal()
    email = session_state.get('email')
    if not email:
        st.error('Primero solicita acceso con tu correo.')
    else:
        # try email token
        if token_in == session_state.get('pending_token'):
            payload = verify_email_token(token_in)
            if payload and payload.get('email') == email:
                session_state['authenticated'] = True
                audit('login_success', {'email': email})
                st.experimental_rerun()
            else:
                st.error('Token inválido o expirado')
                audit('login_fail_token', {'submitted': token_in, 'email': email})
        else:
            # try TOTP
            user = db.query(UserModel).filter_by(email=email).first()
            if user:
                totp = pyotp.TOTP(user.totp_secret)
                if totp.verify(token_in, valid_window=1):
                    session_state['authenticated'] = True
                    audit('login_success_totp', {'email': email})
                    st.experimental_rerun()
                else:
                    st.error('Código inválido')
                    audit('login_fail', {'submitted': token_in, 'email': email})
            else:
                st.error('Usuario no encontrado')
    db.close()
