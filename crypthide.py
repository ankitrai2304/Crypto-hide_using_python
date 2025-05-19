import streamlit as st
import numpy as np
from PIL import Image
import io
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Set page config
st.set_page_config(page_title="Steganography App", page_icon="🕵️", layout="wide")

# UI Styling for Dark Theme
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #A5B4FC;
            padding between: 0px 0px 10px 0px;
    }
    .sub-header {
            padding-top: 10px;
        font-size: 2rem;
        font-size: 1.5rem;
        color: #818CF8;
    }
    .stApp {
        background-color: #111827;
        color: #E5E7EB;
        padding: 20px;
        border-radius: 0.5rem;
        border-radius: 0.5rem;
        padding: 20px;
        border: 1px solid #374151;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
        margin: 20px;`
    }
    .info-box {
        background-color: #1F2937;
        padding: .5rem;
        border-radius: 0.5rem;
        border-left: 4px solid #6366F1;
        color: #D1D5DB;
    }
    div[data-testid="stForm"] {
        background-color: #1F2937;
        border-radius: 0.5rem;
        padding: 1rem;
        border: 1px solid #374151;
    }
    div[data-testid="stVerticalBlock"] div[data-testid="stVerticalBlock"] {
        background-color: transparent;
    }
    div.row-widget.stButton > button {
        background-color: #6366F1;
        color: white;
        border: none;
    }
    div.row-widget.stButton > button:hover {
        background-color: #4F46E5;
    }
    div.row-widget.stTextInput > div > div > input {
        background-color: #374151;
        color: #E5E7EB;
    }
    div.row-widget.stTextArea > div > div > textarea {
        background-color: #374151;
        color: #E5E7EB;
    }
    p, h1, h2, h3, h4, h5, h6, div {
        color: #E5E7EB;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 24px;
    }
    .stTabs [data-baseweb="tab"] {
        height: 50px;
        white-space: pre-wrap;
        background-color: #1F2937;
        border-radius: 152px 56px 116px 45px;
        space-between: 0px;
        padding: 0px 16px;
        color: #9CA3AF;
        font-size: 1rem;
        gap: 1px;
        padding-top: 10px;
        padding-bottom: 10px;
    }
    .stTabs [aria-selected="true"] {
        background-color: #374151;
        border-bottom: 2px solid #6366F1;
    }
    .stExpander {
        background-color: #1F2937;
        border: 1px solid #374151;
    }
    div[data-testid="stFileUploader"] {
        background-color: #1F2937;
        border: 1px dashed #4B5563;
        border-radius: 0.5rem;
    }
    .success-box {
        background-color: #064E3B;
        padding: 10px;
        padding-top: 20px;
        border-radius: 10px;
        margin: 10px 0;
        border-left: 4px solid #10B981;
        color: #D1FAE5;
    }
    .error-box {
        background-color: #7F1D1D;
        padding: 20px;
        border-radius: 10px;
        margin: 10px 0;
        border-left: 4px solid #EF4444;
        color: #FEE2E2;
    }
    .warning-box {
        background-color: #78350F;
        padding: 20px;
        border-radius: 10px;
        margin: 10px 0;
        border-left: 4px solid #F59E0B;
        color: #FEF3C7;
    }
    footer {
        visibility: hidden;
    }
</style>
""", unsafe_allow_html=True)

# Define encryption/decryption functions
def generate_key(password, salt=None):
    """Generate a Fernet key from a password."""
    if salt is None:
        salt = b'steganography_salt'  
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_message(message, password):
    """Encrypt a message using a password."""
    key = generate_key(password)
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    return encrypted_message

def decrypt_message(encrypted_message, password):
    """Decrypt a message using a password."""
    key = generate_key(password)
    f = Fernet(key)
    try:
        decrypted_message = f.decrypt(encrypted_message).decode()
        return decrypted_message
    except Exception as e:
        st.error(f"Decryption failed! Check your password or the image might not contain hidden data.")
        return None

# Define steganography functions
def to_binary(data):
    """Convert data to binary format."""
    if isinstance(data, str):
        return ''.join([format(ord(i), '08b') for i in data])
    elif isinstance(data, bytes):
        return ''.join([format(i, '08b') for i in data])
    elif isinstance(data, np.ndarray):
        return [format(i, '08b') for i in data]
    elif isinstance(data, int) or isinstance(data, np.uint8):
        return format(data, '08b')
    else:
        raise TypeError("Type not supported.")

def encode_data(image, data):
    """Encode data into an image."""
    # Convert data to binary
    binary_data = to_binary(data)
    binary_data += '1111111111111110'  # Delimiter to know when to stop decoding
    
    # Get image dimensions
    height, width, channels = image.shape
    
    # Check if the image is big enough to hide the data
    if len(binary_data) > height * width * channels:
        raise ValueError("Image too small to encode the data. Try a larger image or less data.")
    
    # Encode the data into the image
    data_index = 0
    encoded_image = image.copy()
    
    for i in range(height):
        for j in range(width):
            for k in range(channels):
                if data_index < len(binary_data):
                    # Get the pixel value and convert to binary
                    pixel = to_binary(image[i, j, k])
                    
                    # Replace the least significant bit with the data bit
                    pixel = pixel[:-1] + binary_data[data_index]
                    
                    # Update the image with the new pixel value
                    encoded_image[i, j, k] = int(pixel, 2)
                    
                    data_index += 1
                else:
                    break
    
    return encoded_image

def decode_data(image):
    """Decode data from an image."""
    binary_data = ""
    height, width, channels = image.shape
    
    for i in range(height):
        for j in range(width):
            for k in range(channels):
                # Get the pixel value and extract the least significant bit
                pixel = to_binary(image[i, j, k])
                binary_data += pixel[-1]
                
                # Check if we've reached the delimiter
                if len(binary_data) >= 16 and binary_data[-16:] == '1111111111111110':
                    # Remove the delimiter and return the data
                    binary_data = binary_data[:-16]
                    
                    # Convert the binary data back to bytes
                    byte_data = bytearray()
                    for idx in range(0, len(binary_data), 8):
                        if idx + 8 <= len(binary_data):
                            byte = binary_data[idx:idx+8]
                            byte_data.append(int(byte, 2))
                    
                    return bytes(byte_data)
    
    return None

def get_image_download_link(img, filename, text):
    """Generates a link to download the image."""
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    href = f'<a href="data:file/png;base64,{img_str}" download="{filename}" style="background-color:#6366F1; color:white; padding:0.5rem 1rem; border-radius:0.25rem; text-decoration:none;">{text}</a>'
    return href

# App header
st.markdown('<p class="main-header">🕵️ StegoCrypt: Secure Steganography</p>', unsafe_allow_html=True)
st.markdown("""
<div class="info-box", padding-bottom: 10px;>
Hide your secret messages inside innocent-looking images with military-grade encryption. 
Only someone with both the image and the correct password can reveal your hidden message.
</div>
""", unsafe_allow_html=True)

# Create tabs for encoding and decoding
tab1, tab2 = st.tabs(["🔒 Hide Message", "🔑 Reveal Message"])

with tab1:
    st.markdown('<p class="sub-header" padding-top :10px; >Hide Your Secret Message</p>' , unsafe_allow_html=True)
    
    
    # Create a container with better styling
    with st.container():
        # Get user inputs
        col1, col2 = st.columns([3, 2])
        
        with col1:
            file = st.file_uploader("Upload carrier image (PNG recommended)", type=["png", "jpg", "jpeg"])
            message = st.text_area("Enter your secret message", height=150)
            
        with col2:
            if file:
                st.image(file, caption="Carrier Image", use_column_width=True)
            else:
                st.markdown("""
                <div style="background-color:#1F2937; padding:20px; border-radius:5px; border:1px dashed #4B5563; text-align:center;">
                    <span style="font-size:2rem;">📷</span><br>
                    <span style="color:#9CA3AF;">Please upload an image</span>
                </div>
                """, unsafe_allow_html=True)
        
        password = st.text_input("Enter a password to encrypt your message", type="password")
        
        if st.button("🔐 Hide Message", use_container_width=True) and file is not None and message and password:
            try:
                # Load and process the image
                img = Image.open(file).convert("RGB")
                img_array = np.array(img)
                
                # Encrypt the message
                encrypted_message = encrypt_message(message, password)
                
                # Hide the encrypted message in the image
                with st.spinner("Hiding your message..."):
                    encoded_img_array = encode_data(img_array, encrypted_message)
                    encoded_img = Image.fromarray(encoded_img_array)
                    
                    # Display the result
                    col1, col2 = st.columns(2)
                    with col1:
                        st.image(img, caption="Original Image")
                    with col2:
                        st.image(encoded_img, caption="Image with Hidden Message")
                    
                    # Provide download link
                    st.markdown(f"<div style='text-align: center; margin-top: 20px;'>{get_image_download_link(encoded_img, 'stego_image.png', '📥 Download Image with Hidden Message')}</div>", unsafe_allow_html=True)
                    st.markdown("""
                    <div class="success-box">
                        ✅ Message successfully hidden! Download the image and share it securely.
                    </div>
                    <div class="warning-box">
                        ⚠️ Remember your password! Without it, the message cannot be decrypted.
                    </div>
                    """, unsafe_allow_html=True)
            except Exception as e:
                st.markdown(f"""
                <div class="error-box">
                    ❌ An error occurred: {str(e)}
                </div>
                """, unsafe_allow_html=True)

with tab2:
    st.markdown('<p class="sub-header">Reveal a Hidden Message</p>', unsafe_allow_html=True)
    
    # Create a container with better styling
    with st.container():
        # Get user inputs
        col1, col2 = st.columns([3, 2])
        
        with col1:
            file = st.file_uploader("Upload image with hidden message", type=["png", "jpg", "jpeg"], key="decode_file")
            
        with col2:
            if file:
                st.image(file, caption="Image with Hidden Message", use_column_width=True)
            else:
                st.markdown("""
                <div style="background-color:#1F2937; padding:20px; border-radius:5px; border:1px dashed #4B5563; text-align:center;">
                    <span style="font-size:2rem;">🔍</span><br>
                    <span style="color:#9CA3AF;">Please upload an image with hidden data</span>
                </div>
                """, unsafe_allow_html=True)
        
        password = st.text_input("Enter the password to decrypt the message", type="password", key="decode_password")
        
        if st.button("🔍 Reveal Message", use_container_width=True) and file is not None and password:
            try:
                # Load and process the image
                img = Image.open(file).convert("RGB")
                img_array = np.array(img)
                
                # Extract the hidden data
                with st.spinner("Extracting hidden data..."):
                    extracted_data = decode_data(img_array)
                    
                    if extracted_data:
                        # Decrypt the message
                        decrypted_message = decrypt_message(extracted_data, password)
                        
                        if decrypted_message:
                            st.markdown("""
                            <div class="success-box">
                                ✅ Hidden message successfully revealed!
                            </div>
                            """, unsafe_allow_html=True)
                            
                            # Display the message in a box
                            st.markdown("### Hidden Message:")
                            st.markdown(f"""
                            <div style="background-color:#1F2937; padding:20px; border-radius:10px; margin:10px 0; border-left:4px solid #10B981; color:#D1FAE5;">
                                {decrypted_message}
                            </div>
                            """, unsafe_allow_html=True)
                    else:
                        st.markdown("""
                        <div class="warning-box">
                            ⚠️ No hidden message found in this image.
                        </div>
                        """, unsafe_allow_html=True)
            except Exception as e:
                st.markdown(f"""
                <div class="error-box">
                    ❌ An error occurred: {str(e)}
                </div>
                """, unsafe_allow_html=True)

# Add information about how it works
with st.sidebar:
    st.markdown("## How StegoCrypt Works")
    st.markdown("""
    ### What is Steganography?
    Steganography is the practice of concealing information within ordinary, non-secret data or a physical object to avoid detection.
    
    ### Our Implementation:
    """)
    
    # Create expandable sections
    with st.expander("🔒 Step 1: Encryption"):
        st.markdown("""
        Your message is first encrypted using:
        - Fernet symmetric encryption (AES-128)
        - Password-based key derivation (PBKDF2)
        - This ensures that even if someone detects hidden data, they cannot read it without the password
        """)
    
    with st.expander("🧩 Step 2: LSB Steganography"):
        st.markdown("""
        The encrypted message is hidden in the image by:
        - Converting the encrypted data to binary
        - Replacing the least significant bit (LSB) of each color channel in each pixel
        - Adding a delimiter to mark the end of the message
        - The changes are imperceptible to the human eye
        """)
    
    with st.expander("🔍 Step 3: Extraction & Decryption"):
        st.markdown("""
        To reveal the hidden message:
        - The LSB of each pixel's color channels is extracted
        - The binary data is reconstructed until the delimiter is found
        - The encrypted message is decrypted using the provided password
        - The original message is displayed
        """)
    
    st.markdown("### Security Features:")
    st.markdown("""
    - Visual differences are imperceptible
    - Without the password, the message cannot be decrypted
    - Uses cryptographically secure algorithms
    """)
    
    # Add footer
    st.markdown("---")
    st.markdown("Made with ❤️ by StegoCrypt")
    st.markdown("© 2025 • All rights reserved")