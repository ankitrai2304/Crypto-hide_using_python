🕵️ StegoCrypt: Secure Steganography
A modern, user-friendly steganography application that allows you to hide secret messages inside images with military-grade encryption. Built with Streamlit and featuring a sleek dark theme interface.
Show Image Show Image Show Image
✨ Features

🔐 Double Security: Combines steganography with AES-128 encryption
👁️ Invisible Changes: LSB steganography ensures visual imperceptibility
🎨 Modern UI: Dark theme with intuitive interface
📱 User-Friendly: Simple upload, hide, and reveal workflow
🔒 Password Protected: Messages are encrypted before hiding
📥 Easy Download: One-click download of steganographic images

🚀 How It Works
1. Encryption Layer

Messages are encrypted using Fernet symmetric encryption (AES-128)
PBKDF2 key derivation from user passwords
100,000 iterations for enhanced security

2. Steganography Layer

LSB (Least Significant Bit) technique
Hides encrypted data in image pixel color channels
Adds delimiter to mark message boundaries
Supports PNG, JPG, and JPEG formats

3. Extraction & Decryption

Extracts LSB data from each pixel
Reconstructs encrypted message using delimiter
Decrypts message with user password

🛠️ Installation
Prerequisites

Python 3.7 or higher
pip package manager

Setup Instructions

Clone the repository
bashgit clone https://github.com/yourusername/stegocrypt.git
cd stegocrypt

Install dependencies
bashpip install -r requirements.txt

Run the application
bashstreamlit run app.py

Open in browser

The app will automatically open at http://localhost:8501



📦 Dependencies
Create a requirements.txt file with:
streamlit>=1.28.0
numpy>=1.24.0
Pillow>=9.5.0
cryptography>=41.0.0
🎯 Usage
Hiding a Message

Upload Image: Select a carrier image (PNG recommended for best quality)
Enter Message: Type your secret message in the text area
Set Password: Choose a strong password for encryption
Hide Message: Click "🔐 Hide Message" to process
Download: Save the steganographic image

Revealing a Message

Upload Stego Image: Select the image containing hidden data
Enter Password: Provide the correct decryption password
Reveal Message: Click "🔍 Reveal Message" to extract
View Result: Your secret message will be displayed

🔧 Technical Details
Encryption Specifications

Algorithm: Fernet (AES-128 in CBC mode)
Key Derivation: PBKDF2-HMAC-SHA256
Salt: Fixed salt for consistency
Iterations: 100,000 for security

Steganography Specifications

Method: LSB (Least Significant Bit)
Channels: All RGB channels utilized
Delimiter: 1111111111111110 (16-bit marker)
Capacity: Depends on image size (1 bit per color channel)

Image Format Support

Input: PNG, JPG, JPEG
Output: PNG (recommended for lossless quality)
Processing: Automatic RGB conversion

🛡️ Security Features

Double Protection: Steganography + Encryption
Visual Imperceptibility: Changes undetectable to human eye
Password Dependency: No password = no access
Cryptographic Security: Industry-standard algorithms
No Metadata Leakage: Pure pixel-level hiding

📊 Capacity Calculator
Estimate hiding capacity for your images:
python# For an image of width × height pixels
capacity_bits = width × height × 3  # 3 color channels
capacity_bytes = capacity_bits // 8
capacity_characters = capacity_bytes - 16  # Account for delimiter
Example: A 1920×1080 image can hide approximately 777,600 characters.
⚠️ Important Notes
Best Practices

Use PNG format for carrier images (lossless)
Choose strong passwords (12+ characters)
Test with small messages first
Keep original images as backup

Limitations

File Size: Larger images = more hiding capacity
Compression: JPEG compression may affect hidden data
Detection: Advanced steganalysis tools may detect presence of hidden data

Security Warnings

Steganography provides security through obscurity
Always use additional encryption for sensitive data
Do not rely solely on steganography for critical security

🧪 Example Usage
python# Command line interface (if you want to extend)
from stegocrypt import StegoCrypt

# Initialize
stego = StegoCrypt()

# Hide message
stego.hide_message(
    image_path="carrier.png",
    message="Hello, World!",
    password="supersecret123",
    output_path="hidden.png"
)

# Reveal message
message = stego.reveal_message(
    image_path="hidden.png",
    password="supersecret123"
)
print(message)  # "Hello, World!"
🔍 Troubleshooting
Common Issues
"Image too small to encode the data"

Solution: Use a larger image or shorter message

"Decryption failed"

Check password spelling and case sensitivity
Ensure image hasn't been compressed or modified

"No hidden message found"

Verify you're using the correct stego image
Check if image was saved in lossy format

Performance Issues

Large images may take time to process
Consider resizing extremely large images

🤝 Contributing
Contributions are welcome! Please follow these guidelines:

Fork the repository
Create a feature branch (git checkout -b feature/amazing-feature)
Commit your changes (git commit -m 'Add amazing feature')
Push to the branch (git push origin feature/amazing-feature)
Open a Pull Request

Development Setup
bash# Clone your fork
git clone https://github.com/yourusername/stegocrypt.git

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements.txt
pip install pytest black flake8

# Run tests
pytest tests/

# Format code
black .
📄 License
This project is licensed under the MIT License - see the LICENSE file for details.
🙏 Acknowledgments

Streamlit team for the amazing web framework
Cryptography library maintainers
PIL/Pillow contributors
NumPy community

📞 Support

Issues: GitHub Issues
Discussions: GitHub Discussions
Email: ankitrai9977363200@gmail.com

🔮 Future Enhancements

 Support for more image formats (TIFF, BMP)
 Multiple encryption algorithms
 Batch processing capabilities
 Mobile-responsive design improvements
 Command-line interface
 Docker containerization
 API endpoints for integration


⚠️ Disclaimer: This tool is for educational and legitimate privacy purposes only. Users are responsible for complying with applicable laws and regulations.
