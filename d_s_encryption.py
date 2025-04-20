import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Generate encryption key (should be stored securely in real apps)
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# In-memory store
stored_data = {}  # Format: { "encrypted_text": {"passkey": hashed_passkey} }

# Session state for tracking login attempts
if "failed_attempts" not in st.session_state:
    st.session_state["failed_attempts"] = 0

# Helper functions
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(data):
    return cipher.encrypt(data.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    hashed = hash_passkey(passkey)
    if encrypted_text in stored_data and stored_data[encrypted_text]["passkey"] == hashed:
        st.session_state["failed_attempts"] = 0
        return cipher.decrypt(encrypted_text.encode()).decode()
    else:
        st.session_state["failed_attempts"] += 1
        return None

# Page settings
st.set_page_config(page_title="🔐 Sterling Secure Vault", page_icon="🔐", layout="wide")

# Custom CSS to move menu to the right
st.markdown("""
    <style>
    [data-testid="stSidebar"] {
        right: 0;
        left: auto;
        background-color: #f5f5f5;
        box-shadow: -2px 0 5px rgba(0,0,0,0.1);
    }
    .css-1lcbmhc {  /* Optional: align main content away from sidebar */
        margin-right: 250px;
    }
    </style>
""", unsafe_allow_html=True)

# App header
st.markdown("<h1 style='text-align: center;'>🔐 Sterling Secure Vault</h1>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center; color: gray;'>A sleek app to securely store and retrieve your sensitive data</p>", unsafe_allow_html=True)

# Navigation menu (right-aligned now)
menu = ["🏠 Home", "📂 Store Data", "🔍 Retrieve Data", "🔑 Login"]
choice = st.sidebar.radio("📁 Navigate", menu)

# Home Page
if choice == "🏠 Home":
    st.info("Welcome to **Sterling Secure Vault**! This app helps you encrypt and decrypt your sensitive information using passkey-based protection.")
    st.markdown("### 🔧 Features:")
    st.markdown("- 🔒 Encrypt and store sensitive information")
    st.markdown("- 🧪 Decrypt only with the correct passkey")
    st.markdown("- 🚫 Login lock after 3 failed attempts")
    st.markdown("- 🔑 Master login to reset access")

# Store Encrypted Data
elif choice == "📂 Store Data":
    st.subheader("📦 Store New Encrypted Data")
    user_data = st.text_area("📝 Enter your secret data:", height=150)
    passkey = st.text_input("🔑 Choose a secure passkey:", type="password")

    if st.button("🚀 Encrypt & Store"):
        if user_data and passkey:
            encrypted = encrypt_data(user_data)
            stored_data[encrypted] = {"passkey": hash_passkey(passkey)}
            st.success("✅ Successfully encrypted and stored your data!")
            st.code(encrypted, language="text")
        else:
            st.warning("⚠️ Please provide both data and passkey.")

# Retrieve Encrypted Data
elif choice == "🔍 Retrieve Data":
    st.subheader("🔎 Decrypt Stored Data")

    if st.session_state["failed_attempts"] >= 3:
        st.error("🚫 You have exceeded the maximum number of attempts.")
        st.info("Please login from the sidebar to reset access.")
    else:
        encrypted_input = st.text_area("🔐 Paste the encrypted text here:")
        passkey_input = st.text_input("🗝️ Enter your passkey:", type="password")

        if st.button("🔓 Decrypt"):
            if encrypted_input and passkey_input:
                result = decrypt_data(encrypted_input, passkey_input)
                if result:
                    st.success("✅ Data decrypted successfully!")
                    st.code(result, language='text')
                else:
                    remaining = 3 - st.session_state["failed_attempts"]
                    st.error(f"❌ Incorrect passkey. Attempts remaining: {remaining}")
            else:
                st.warning("⚠️ Please enter both fields to proceed.")

# Login Page
elif choice == "🔑 Login":
    st.subheader("🔐 Master Login")
    master_pass = st.text_input("Enter the master password to reset access:", type="password")

    if st.button("✅ Login"):
        if master_pass == "admin123":
            st.session_state["failed_attempts"] = 0
            st.success("🔓 Access reset successful. You may now try decrypting again.")
        else:
            st.error("❌ Incorrect master password.")
