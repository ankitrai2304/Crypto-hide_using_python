import os
import argparse
import smtplib
import base64
import json
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
# from cryptography.fernet import Fernet
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PIL import Image

class SteganographyTool:
    def __init__(self):
        self.salt = b'steganography_salt_value'  # In production, use a secure random salt
    
    def generate_key(self, password):
        """Generate a Fernet key from a password."""
        password_bytes = password.encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
        return key
    
    def encrypt_data(self, data, password):
        """Encrypt data using the password."""
        key = self.generate_key(password)
        f = Fernet(key)
        encrypted_data = f.encrypt(data.encode())
        return encrypted_data
    
    def decrypt_data(self, encrypted_data, password):
        """Decrypt data using the password."""
        key = self.generate_key(password)
        f = Fernet(key)
        decrypted_data = f.decrypt(encrypted_data)
        return decrypted_data.decode()
    
    def encode_image(self, image_path, data, password, output_path):
        """Hide encrypted data in an image."""
        # Encrypt the data first
        encrypted_data = self.encrypt_data(data, password)
        
        # Convert encrypted data to binary
        binary_data = ''.join(format(byte, '08b') for byte in encrypted_data)
        
        # Open the image
        image = Image.open(image_path)
        width, height = image.size
        
        # Check if the image can store the data
        max_bytes = (width * height * 3) // 8
        data_len = len(binary_data)
        
        if data_len > max_bytes:
            raise ValueError(f"Data too large for image. Max bytes: {max_bytes}, Data bytes: {data_len//8}")
        
        # Convert image to RGB if it's not already
        if image.mode != 'RGB':
            image = image.convert('RGB')
        
        # Add length of data at the beginning for extraction
        length_binary = format(len(binary_data), '032b')
        binary_data = length_binary + binary_data
        
        # Create a new image to store the data
        encoded_image = image.copy()
        pixels = list(encoded_image.getdata())
        
        # Embed data in the least significant bit of each color channel
        data_index = 0
        new_pixels = []
        
        for pixel in pixels:
            r, g, b = pixel
            
            # Modify pixels only if there's still data to embed
            if data_index < len(binary_data):
                r = (r & ~1) | int(binary_data[data_index])
                data_index += 1
            
            if data_index < len(binary_data):
                g = (g & ~1) | int(binary_data[data_index])
                data_index += 1
            
            if data_index < len(binary_data):
                b = (b & ~1) | int(binary_data[data_index])
                data_index += 1
            
            new_pixels.append((r, g, b))
            
            if data_index >= len(binary_data):
                break
        
        # Update the first pixels with our data and keep the rest unchanged
        remaining_pixels = len(pixels) - len(new_pixels)
        new_pixels.extend(pixels[len(new_pixels):])
        
        # Update the image with new pixel data
        encoded_image.putdata(new_pixels)
        
        # Save the image
        encoded_image.save(output_path)
        print(f"Data hidden in {output_path}")
        
        return output_path
    
    def decode_image(self, image_path, password):
        """Extract hidden data from an image and decrypt it."""
        # Open the image
        image = Image.open(image_path)
        
        # Get pixel data
        pixels = list(image.getdata())
        
        # Extract the least significant bits
        binary_data = ""
        for pixel in pixels:
            r, g, b = pixel
            binary_data += str(r & 1)
            binary_data += str(g & 1)
            binary_data += str(b & 1)
        
        # First 32 bits represent the length of the hidden data
        data_length = int(binary_data[:32], 2)
        
        # Extract the actual data bits
        extracted_binary = binary_data[32:32+data_length]
        
        # Convert binary string to bytes
        extracted_bytes = bytearray()
        for i in range(0, len(extracted_binary), 8):
            if i + 8 <= len(extracted_binary):
                byte = extracted_binary[i:i+8]
                extracted_bytes.append(int(byte, 2))
        
        # Decrypt the data
        try:
            decrypted_data = self.decrypt_data(bytes(extracted_bytes), password)
            return decrypted_data
        except Exception as e:
            print(f"Error decrypting data: {e}")
            return None

class EmailSender:
    def __init__(self, smtp_server, smtp_port, username, password):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
    
    def send_email(self, recipient_email, subject, body, image_path=None, decryption_info=None):
        """Send an email with optional image attachment and decryption instructions."""
        # Create message
        msg = MIMEMultipart()
        msg['From'] = self.username
        msg['To'] = recipient_email
        msg['Subject'] = subject
        
        # Add body
        msg.attach(MIMEText(body, 'plain'))
        
        # If decryption info is provided, add it as a separate part
        if decryption_info:
            decryption_text = f"""
            DECRYPTION INSTRUCTIONS:
            
            1. Save the attached image
            2. Use the steganography tool to extract the hidden message
            3. Use the following password to decrypt: {decryption_info.get('password', '[PASSWORD NOT PROVIDED]')}
            
            Additional notes: {decryption_info.get('notes', '')}
            """
            msg.attach(MIMEText(decryption_text, 'plain'))
        
        # Add image if provided
        if image_path and os.path.isfile(image_path):
            with open(image_path, 'rb') as img:
                image_data = img.read()
                image = MIMEImage(image_data, name=os.path.basename(image_path))
                msg.attach(image)
        
        # Connect to server and send
        try:
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()  # Enable TLS encryption
            server.login(self.username, self.password)
            server.send_message(msg)
            server.quit()
            print(f"Email sent successfully to {recipient_email}")
            return True
        except Exception as e:
            print(f"Failed to send email: {e}")
            return False

def main():
    parser = argparse.ArgumentParser(description='Steganography Tool with Email Functionality')
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Hide command
    hide_parser = subparsers.add_parser('hide', help='Hide data in an image')
    hide_parser.add_argument('--image', required=True, help='Path to the cover image')
    hide_parser.add_argument('--data', required=True, help='Data to hide')
    hide_parser.add_argument('--password', required=True, help='Password for encryption')
    hide_parser.add_argument('--output', required=True, help='Output image path')
    hide_parser.add_argument('--send-email', action='store_true', help='Send the image via email')
    hide_parser.add_argument('--recipient', help='Email recipient (required if send-email is used)')
    hide_parser.add_argument('--config', help='Path to email configuration JSON file')
    
    # Extract command
    extract_parser = subparsers.add_parser('extract', help='Extract data from an image')
    extract_parser.add_argument('--image', required=True, help='Path to the steganographic image')
    extract_parser.add_argument('--password', required=True, help='Password for decryption')
    
    # Setup command
    setup_parser = subparsers.add_parser('setup', help='Create email configuration file')
    setup_parser.add_argument('--output', required=True, help='Path for the configuration file')
    
    args = parser.parse_args()
    
    steg_tool = SteganographyTool()
    
    if args.command == 'hide':
        # Hide data in image
        output_path = steg_tool.encode_image(args.image, args.data, args.password, args.output)
        
        # Send email if requested
        if args.send_email:
            if not args.recipient:
                print("Error: Recipient email is required when using --send-email")
                return
                
            if not args.config or not os.path.isfile(args.config):
                print("Error: Valid email configuration file is required")
                return
                
            # Load email configuration
            with open(args.config, 'r') as f:
                config = json.load(f)
                
            email_sender = EmailSender(
                config['smtp_server'],
                config['smtp_port'],
                config['username'],
                config['password']
            )
            
            # Create decryption info (don't include the actual password in a real scenario)
            decryption_info = {
                'password': args.password,  # In real app, send this separately or via another channel
                'notes': 'This image contains encrypted data. Use the steganography tool to extract it.'
            }
            
            # Send email
            email_sender.send_email(
                args.recipient,
                "Steganographic Image",
                "Please find attached an image with hidden information.",
                output_path,
                decryption_info
            )
            
    elif args.command == 'extract':
        # Extract and decrypt data
        extracted_data = steg_tool.decode_image(args.image, args.password)
        if extracted_data:
            print(f"Extracted message: {extracted_data}")
        else:
            print("Failed to extract data or incorrect password")
            
    elif args.command == 'setup':
        # Create email configuration template
        config = {
            'smtp_server': 'smtp.gmail.com',  # Example for Gmail
            'smtp_port': 587,
            'username': 'your_email@gmail.com',
            'password': 'your_app_password'  # Use app passwords for Gmail
        }
        
        with open(args.output, 'w') as f:
            json.dump(config, f, indent=4)
        print(f"Email configuration template created at {args.output}")
        print("Please edit this file with your actual email credentials")
        
    else:
        parser.print_help()

if __name__ == "__main__":
    main()