import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import streamlit.components.v1 as components

# -- Encryption setup --
KEY = Fernet.generate_key()
cipher = Fernet(KEY)
stored_data = {}

if "failed_attempts" not in st.session_state:
    st.session_state["failed_attempts"] = 0

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

# -- Page config & styles --
st.set_page_config(page_title="Sterling Secure Vault", page_icon="🔐", layout="wide")

st.markdown("""
    <style>
        body {
            background-color: #f8f9fa;
        }
        .main {
            background-color: #ffffff;
            border-radius: 15px;
            padding: 2rem;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }
        .stTextInput>div>div>input, .stTextArea textarea {
            background-color: #f3f3f3;
            border-radius: 10px;
        }
        .stButton button {
            background-color: #3b82f6;
            color: white;
            border: none;
            border-radius: 10px;
            padding: 0.5rem 1rem;
            transition: all 0.3s ease;
        }
        .stButton button:hover {
            background-color: #2563eb;
        }
    </style>
""", unsafe_allow_html=True)

# -- Lottie animation loader (Home) --
def load_lottie():
    lottie_url = "https://assets10.lottiefiles.com/packages/lf20_tljjah3d.json"
    components.iframe("https://lottie.host/embed/f4579601-3907-414b-82d4-21b253ad4828/3eOjOgmu5L.json", height=250, scrolling=False)

# -- Sidebar Menu --
menu = ["🏠 Home", "📂 Store Data", "🔍 Retrieve Data", "🔑 Login"]
choice = st.sidebar.selectbox("🔘 Menu", menu)

# -- Home Page --
if choice == "🏠 Home":
    st.markdown("<div class='main'>", unsafe_allow_html=True)
    st.markdown("## 🔐 Welcome to Sterling Secure Vault")
    load_lottie()
    st.write("""
        This app provides **passkey-protected encryption** to store your sensitive data securely.
        \n🧰 Features include:
        - End-to-end encryption using Fernet
        - 3 login attempt restrictions
        - Reset access with a master pass
    """)
    st.markdown("</div>", unsafe_allow_html=True)

# -- Store Data --
elif choice == "📂 Store Data":
    st.markdown("<div class='main'>", unsafe_allow_html=True)
    st.markdown("## 📦 Encrypt & Store Data")
    user_data = st.text_area("🔏 Enter your secret data:")
    passkey = st.text_input("🔑 Choose a passkey:", type="password")
    if st.button("🚀 Encrypt Now"):
        if user_data and passkey:
            encrypted = encrypt_data(user_data)
            stored_data[encrypted] = {"passkey": hash_passkey(passkey)}
            st.success("✅ Data encrypted and stored!")
            st.code(encrypted, language='text')
        else:
            st.warning("⚠️ Please fill in both fields.")
    st.markdown("</div>", unsafe_allow_html=True)

# -- Retrieve Data --
elif choice == "🔍 Retrieve Data":
    st.markdown("<div class='main'>", unsafe_allow_html=True)
    st.markdown("## 🔍 Retrieve & Decrypt Data")
    if st.session_state["failed_attempts"] >= 3:
        st.error("🚫 Too many failed attempts.")
        st.info("🔑 Please login to reset.")
    else:
        encrypted_input = st.text_area("🔐 Paste encrypted data:")
        passkey_input = st.text_input("🗝️ Enter your passkey:", type="password")
        if st.button("🔓 Decrypt"):
            if encrypted_input and passkey_input:
                result = decrypt_data(encrypted_input, passkey_input)
                if result:
                    st.success("✅ Decryption successful!")
                    st.code(result, language='text')
                else:
                    remaining = 3 - st.session_state["failed_attempts"]
                    st.error(f"❌ Wrong passkey. {remaining} attempts left.")
            else:
                st.warning("⚠️ Enter both fields.")
    st.markdown("</div>", unsafe_allow_html=True)

# -- Login Reset --
elif choice == "🔑 Login":
    st.markdown("<div class='main'>", unsafe_allow_html=True)
    st.markdown("## 🔐 Master Login")
    master_pass = st.text_input("Enter master password to reset:", type="password")
    if st.button("✅ Login"):
        if master_pass == "admin123":
            st.session_state["failed_attempts"] = 0
            st.success("🔓 Access reset. Try decryption again.")
        else:
            st.error("❌ Incorrect master password.")
    st.markdown("</div>", unsafe_allow_html=True)
