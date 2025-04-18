import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Title
st.markdown("""
<h1 style='
    font-size: 48px;
    display: flex;
    align-items: center;
'>
<img src='https://img.icons8.com/color/48/puzzle.png' style='margin-right: 10px;'/> 
<span style='
    background: linear-gradient(to right, #1e90ff, #ff1493, #ffa500, #32cd32);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
'>Secure Data Encryption</span>
</h1>
""", unsafe_allow_html=True)

# Session state for attempts
if "attempts_left" not in st.session_state:
    st.session_state.attempts_left = 3

# In-memory storage
locker = {}

# Generate and store key securely
SECRET_KEY = Fernet.generate_key()
fernet = Fernet(SECRET_KEY)

# Hashing function
def hash_key(key):
    return hashlib.sha256(key.encode()).hexdigest()

# Encryption function
def encrypt_message(message, key):
    encrypted = fernet.encrypt(message.encode())
    return encrypted.decode()

# Decryption function
def decrypt_message(enc_message, key):
    hashed = hash_key(key)
    for item in locker.values():
        if item["encrypted"] == enc_message and item["hashed_key"] == hashed:
            st.session_state.attempts_left = 3
            return fernet.decrypt(enc_message.encode()).decode()
    st.session_state.attempts_left -= 1
    return None

# Navigation Menu
menu = ["Dashboard", "Encrypt Data", "Decrypt Data", "Admin Login", "About"]
page = st.sidebar.selectbox("📂 Navigate", menu)

# Pages
if page == "Dashboard":
    st.subheader("📌 Welcome to Secure Data Encryption")
    st.write("This app allows you to **encrypt and secure** your data using a private key. Only the correct key can decrypt it.")

elif page == "Encrypt Data":
    st.subheader("🔒 Encrypt Your Data")
    msg = st.text_area("Enter your secret message:")
    key = st.text_input("Set a secret key:", type="password")
    if st.button("Encrypt & Save"):
        if msg and key:
            hashed = hash_key(key)
            enc_msg = encrypt_message(msg, key)
            locker[enc_msg] = {"encrypted": enc_msg, "hashed_key": hashed}
            st.success("✅ Your data has been encrypted securely!")
            st.code(enc_msg, language="text")
        else:
            st.warning("Please fill in both fields.")

elif page == "Decrypt Data":
    st.subheader("🔓 Decrypt Your Data")
    encrypted_input = st.text_area("Paste the encrypted data:")
    key_input = st.text_input("Enter your key:", type="password")
    if st.button("Decrypt"):
        if encrypted_input and key_input:
            result = decrypt_message(encrypted_input, key_input)
            if result:
                st.success(f"✅ Decrypted Data: {result}")
            else:
                st.error(f"❌ Incorrect key. Attempts left: {st.session_state.attempts_left}")
                if st.session_state.attempts_left <= 0:
                    st.warning("🚫 Too many failed attempts! Please login again.")
                    st.experimental_rerun()
        else:
            st.warning("Both fields are required.")

elif page == "Admin Login":
    st.subheader("🔐 Admin Panel")
    master_key = st.text_input("Enter Admin Password:", type="password")
    if st.button("Login"):
        if master_key == "admin321":
            st.session_state.attempts_left = 3
            st.success("🔁 Reset successful. You may now try decrypting again.")
        else:
            st.error("❌ Incorrect admin password!")

elif page == "About":
    st.subheader("ℹ️ About This App")
    st.write("""
    **Secure Data Encryption** is a simple app built with **Streamlit** and **Python** to help you protect and retrieve sensitive data.

    ✅ Encrypt messages securely  
    🔐 Decrypt with the correct passkey  
    🚫 Lockout after failed attempts  
    🛠 Admin access to reset attempts  
    """)
