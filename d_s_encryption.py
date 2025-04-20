import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Key for encryption (in real apps, this should be secret)
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# In-memory data and tracking
stored_data = {}  # Format: { "encrypted_text": {"passkey": hashed_passkey} }

# ✅ Initialize session state
if "failed_attempts" not in st.session_state:
    st.session_state["failed_attempts"] = 0

# Hash passkey using SHA-256
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt the user data
def encrypt_data(data):
    return cipher.encrypt(data.encode()).decode()

# Decrypt data (only if passkey is correct)
def decrypt_data(encrypted_text, passkey):
    hashed = hash_passkey(passkey)

    if encrypted_text in stored_data and stored_data[encrypted_text]["passkey"] == hashed:
        st.session_state["failed_attempts"] = 0
        return cipher.decrypt(encrypted_text.encode()).decode()
    else:
        st.session_state["failed_attempts"] += 1
        return None

# Streamlit UI
st.set_page_config(page_title="🔐 Secure Data App")
st.title("🔐 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Menu", menu)

#HOME
if choice == "Home":
    st.subheader("🏠 Welcome!")
    st.write("Use this app to store and retrieve data securely using encryption and passkeys.")

#STORE DATA
elif choice == "Store Data":
    st.subheader("📂 Store Encrypted Data")
    user_data = st.text_area("Enter your secret data:")
    passkey = st.text_input("Enter a passkey:", type="password")

    if st.button("Encrypt & Store"):
        if user_data and passkey:
            encrypted = encrypt_data(user_data)
            stored_data[encrypted] = {"passkey": hash_passkey(passkey)}
            st.success("✅ Data encrypted and stored successfully!")
            st.code(encrypted, language='text')
        else:
            st.warning("⚠️ Both fields are required.")

#RETRIEVE DATA
elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Encrypted Data")
    encrypted_input = st.text_area("Enter encrypted text:")
    passkey_input = st.text_input("Enter your passkey:", type="password")

    if st.button("Decrypt"):
        if st.session_state["failed_attempts"] >= 3:
            st.warning("🚫 Too many failed attempts. Redirecting to login page.")
            st.experimental_rerun()
        elif encrypted_input and passkey_input:
            result = decrypt_data(encrypted_input, passkey_input)
            if result:
                st.success("✅ Data decrypted successfully:")
                st.code(result, language='text')
            else:
                remaining = 3 - st.session_state["failed_attempts"]
                st.error(f"❌ Incorrect passkey! Attempts remaining: {remaining}")
        else:
            st.warning("⚠️ Please enter both fields.")

#LOGIN
elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    master_pass = st.text_input("Enter master password:", type="password")

    if st.button("Login"):
        if master_pass == "admin123":  # Hardcoded password
            st.session_state["failed_attempts"] = 0
            st.success("✅ Login successful. You can now try again.")
        else:
            st.error("❌ Incorrect master password.")
