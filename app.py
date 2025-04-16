import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# ✅ Must be the first Streamlit command
st.set_page_config(page_title="Secure Encryption System", page_icon="🛡️")

# --- Generate key for encryption ---
if "FERNET_KEY" not in st.session_state:
    st.session_state.FERNET_KEY = Fernet.generate_key()
cipher = Fernet(st.session_state.FERNET_KEY)

# --- Initialize session state ---
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "authorized" not in st.session_state:
    st.session_state.authorized = True

# --- Functions ---
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)

    for value in st.session_state.stored_data.values():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            st.session_state.failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()

    st.session_state.failed_attempts += 1
    return None

# --- UI Layout ---
st.title("🛡️ Secure Data Encryption System")

# --- Navigation ---
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("🔎 Navigate", menu)

# --- Pages ---
if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("This system lets you **securely store and retrieve data** using passkeys.")
    st.info("Use the sidebar to go to different pages.")

elif choice == "Store Data":
    st.subheader("📂 Store Encrypted Data")
    user_text = st.text_area("Enter data to encrypt:")
    passkey = st.text_input("Enter a passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_text and passkey:
            hashed = hash_passkey(passkey)
            encrypted = encrypt_data(user_text)
            st.session_state.stored_data[encrypted] = {
                "encrypted_text": encrypted,
                "passkey": hashed
            }
            st.success("✅ Data encrypted and saved!")
            st.code(encrypted, language='text')
        else:
            st.warning("⚠️ Please enter both data and a passkey.")

elif choice == "Retrieve Data":
    if not st.session_state.authorized:
        st.warning("🔐 Too many failed attempts. Please login again.")
        st.stop()

    st.subheader("🔍 Retrieve Encrypted Data")
    encrypted_input = st.text_area("Paste the encrypted text:")
    passkey = st.text_input("Enter your passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_input and passkey:
            result = decrypt_data(encrypted_input, passkey)
            if result:
                st.success("✅ Decrypted Text:")
                st.code(result, language='text')
            else:
                attempts_left = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts left: {attempts_left}")

                if st.session_state.failed_attempts >= 3:
                    st.session_state.authorized = False
                    st.warning("🔒 Too many failed attempts. Please login.")
                    st.experimental_rerun()
        else:
            st.warning("⚠️ Please enter both encrypted text and passkey.")

elif choice == "Login":
    st.subheader("🔑 Login for Reauthorization")
    login_pass = st.text_input("Enter master password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":
            st.session_state.failed_attempts = 0
            st.session_state.authorized = True
            st.success("✅ Logged in successfully!")
            st.experimental_rerun()
        else:
            st.error("❌ Invalid password.")
