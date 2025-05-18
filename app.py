
import streamlit as st
import hashlib
import hashlib
import time
from cryptography.fernet import Fernet
import base64
import uuid

# ------------------------ Styling ------------------------
st.set_page_config(page_title="Secure Vault", layout="centered")

st.markdown("""
    <style>
    .main {
        background-color: #f4f6f9;
        padding: 20px;
        border-radius: 10px;
    }
    .block-container {
        padding-top: 2rem;
    }
    .title-style {
        font-size: 2.5em;
        color: #3B82F6;
        font-weight: bold;
    }
    .subtitle {
        color: #6B7280;
        margin-bottom: 1rem;
    }
    </style>
""", unsafe_allow_html=True)

# ------------------------ Session Initialization ------------------------
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}
if 'current_page' not in st.session_state:
    st.session_state.current_page = "Home"
if 'last_attempt_time' not in st.session_state:
    st.session_state.last_attempt_time = 0
if 'master_password' not in st.session_state:
    st.session_state.master_password = "admin123"

# ------------------------ Utility Functions ------------------------
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def generate_key_from_passkey(passkey):
    hashed = hashlib.sha256(passkey.encode()).digest()
    return base64.urlsafe_b64encode(hashed[:32])

def encrypt_data(text, passkey):
    key = generate_key_from_passkey(passkey)
    cipher = Fernet(key)
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey, data_id):
    try:
        hashed_passkey = hash_passkey(passkey)
        if data_id in st.session_state.stored_data and st.session_state.stored_data[data_id]["passkey"] == hashed_passkey:
            key = generate_key_from_passkey(passkey)
            cipher = Fernet(key)
            decrypted = cipher.decrypt(encrypted_text.encode()).decode()
            st.session_state.failed_attempts = 0
            return decrypted
        else:
            st.session_state.failed_attempts += 1
            st.session_state.last_attempt_time = time.time()
            return None
    except Exception:
        st.session_state.failed_attempts += 1
        st.session_state.last_attempt_time = time.time()
        return None

def generate_data_id():
    return str(uuid.uuid4())

def reset_failed_attempts():
    st.session_state.failed_attempts = 0

def change_page(page):
    st.session_state.current_page = page

def set_master_password(password):
    st.session_state.master_password = password

# ------------------------ App Title ------------------------
st.markdown('<div class="main">', unsafe_allow_html=True)
st.markdown('<div class="title-style"> Secure Data Vault</div>', unsafe_allow_html=True)
st.markdown('<div class="subtitle">Your private encryption companion</div>', unsafe_allow_html=True)

# ------------------------ Navigation ------------------------
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.radio(" Navigate", menu, index=menu.index(st.session_state.current_page))
st.session_state.current_page = choice

if st.session_state.failed_attempts >= 3:
    st.session_state.current_page = "Login"
    st.warning(" Too many failed attempts! Reauthorization required.")

# ------------------------ Page: Home ------------------------
if st.session_state.current_page == "Home":
    st.subheader(" Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("📥 Store New Data", use_container_width=True):
            change_page("Store Data")
    with col2:
        if st.button("📤 Retrieve Data", use_container_width=True):
            change_page("Retrieve Data")

    st.info(f" Stored Entries: `{len(st.session_state.stored_data)}`")

# ------------------------ Page: Store Data ------------------------
elif st.session_state.current_page == "Store Data":
    st.subheader(" Store Your Secret Data")

    user_data = st.text_area("Enter Data:", placeholder="Type your secret here...")
    passkey = st.text_input("Enter Passkey:", type="password", placeholder="Create a strong passkey")
    confirm_passkey = st.text_input("Confirm Passkey:", type="password", placeholder="Re-enter your passkey")

    if st.button(" Encrypt & Save"):
        if user_data and passkey and confirm_passkey:
            if passkey != confirm_passkey:
                st.error(" Passkeys do not match!")
            else:
                data_id = generate_data_id()
                hashed_passkey = hash_passkey(passkey)
                encrypted_text = encrypt_data(user_data, passkey)

                st.session_state.stored_data[data_id] = {
                    "encrypted_text": encrypted_text,
                    "passkey": hashed_passkey
                }

                st.success(" Data stored securely!")
                st.code(data_id, language="text")
                st.info("📌 Save this Data ID for future retrieval.")
        else:
            st.error(" All fields are required!")

# ------------------------ Page: Retrieve Data ------------------------
elif st.session_state.current_page == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Secret")

    attempts_remaining = 3 - st.session_state.failed_attempts
    st.info(f" Attempts remaining: {attempts_remaining}")

    data_id = st.text_input("Enter Data ID:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button(" Decrypt"):
        if data_id and passkey:
            if data_id in st.session_state.stored_data:
                encrypted_text = st.session_state.stored_data[data_id]["encrypted_text"]
                decrypted_text = decrypt_data(encrypted_text, passkey, data_id)

                if decrypted_text:
                    st.success(" Decryption successful!")
                    st.markdown("### 🔎 Decrypted Result:")
                    st.code(decrypted_text, language="text")
                else:
                    st.error(f"❌ Incorrect passkey! {3 - st.session_state.failed_attempts} attempts left.")
            else:
                st.error("❌ Data ID not found!")

            if st.session_state.failed_attempts >= 3:
                st.warning(" Too many failed attempts. Redirecting...")
                st.session_state.current_page = "Login"
                st.rerun()
        else:
            st.error(" Both fields are required!")

# ------------------------ Page: Login ------------------------
elif st.session_state.current_page == "Login":
    st.subheader(" Reauthentication")

    wait_time = 10
    if time.time() - st.session_state.last_attempt_time < wait_time and st.session_state.failed_attempts >= 3:
        remaining_time = int(wait_time - (time.time() - st.session_state.last_attempt_time))
        st.warning(f" Please wait {remaining_time} seconds before trying again.")
    else:
        login_pass = st.text_input("Enter Master Password:", type="password")

        if st.button(" Login"):
            if login_pass == st.session_state.master_password:
                reset_failed_attempts()
                st.success("✅ Access restored!")
                st.session_state.current_page = "Home"
                st.rerun()
            else:
                st.error(" Incorrect password!")

        if st.button(" Change Master Password"):
            new_pass = st.text_input("Enter New Master Password:", type="password")
            confirm_new_pass = st.text_input("Confirm New Master Password:", type="password")

            if st.button(" Save New Master Password"):
                if new_pass and confirm_new_pass:
                    if new_pass != confirm_new_pass:
                        st.error(" Passwords do not match!")
                    else:
                        set_master_password(new_pass)
                        st.success("✅ Master password changed!")
                else:
                    st.error(" All fields are required!")
