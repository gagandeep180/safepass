![safe pass ](/screenshot/project.png ) 

🔐 Secure Password Manager Suite
The Secure Password Manager Suite is a desktop application built using Python that allows users to safely store, manage, and retrieve their passwords. It is designed with security as a priority, offering PIN protection, encryption, and a user-friendly interface to manage credentials efficiently.

##  Features 
### 🔒 Security

* PIN Protection: 4-6 digit PIN authentication system
* Encryption: All passwords encrypted using Fernet (symmetric encryption)
* Secure Hashing: PINs are hashed using SHA-256 before storage
* Lockout Protection: 3 failed PIN attempts locks the application
### 🥷🏻 Password Management
- *Save*: Store new passwords with site/service name and username
- *Update*: Modify existing password entries
- *Delete*: Remove password entries with confirmation
- *View All*: Display all stored passwords in a clean format
- *Duplicate Prevention*: Warns if entry already exists

### 📊 Export & Backup
- *Excel Export*: Export all passwords to an XLSX file for backup
- Decrypted passwords included in export for easy access

### 🎨 User Interface
- Clean and modern GUI using Tkinter
- Color-coded buttons for different actions
- Status messages for user feedback
- Scrollable password display area

## Installation
save the safepass.py file 
 ### Prerequisites
bash
pip install cryptography openpyxl
 ### Required Packages
- tkinter (usually comes with Python)
- cryptography - For password encryption
- openpyxl - For Excel export functionality
- sqlite3 (built-in) - Database management
- hashlib (built-in) - PIN hashing

## Usage

### First Time Setup
1. Run the application
2. Create a 4-6 digit PIN when prompted
3. Confirm your PIN
4. The vault is now ready to use

### Adding Passwords
1. Enter the site/service name
2. Enter your username/email
3. Enter the password
4. Click *Save*

### Viewing Passwords
- Click *View All* to display all stored passwords
- Passwords are automatically loaded on startup

### Updating Passwords
1. Enter the exact site name and username
2. Enter the new password
3. Click *Update*

### Deleting Passwords
1. Enter the site name and username
2. Click *Delete*
3. Confirm the deletion

### Exporting to Excel
1. Click *Export Excel*
2. Choose save location
3. Excel file contains all decrypted passwords

### Changing PIN
1. Click *Change PIN*
2. Verify current PIN
3. Enter and confirm new PIN

## File Structure

"""text
password-manager/
├── password_manager.py    # Main application file
├── key.key               # Encryption key (auto-generated)
├── pin.hash              # Hashed PIN (auto-generated)
└── vault.db              # SQLite database (auto-generated)

## Database Schema

* Table: vault *
sql
CREATE TABLE vault (
    site TEXT,      -- Website/service name
    user TEXT,      -- Username/email
    pwd BLOB        -- Encrypted password
)

*Important Security Information:*

1. *Keep key.key safe*: This file encrypts all your passwords. If lost, passwords cannot be recovered.
2. *Remember your PIN*: After 3 failed attempts, the application locks for security.
3. *Backup regularly*: Use the Excel export feature to create backups.
4. *Store backups securely*: Excel exports contain unencrypted passwords.
5. *Never share*: Don't share your key.key file or PIN with anyone.

## Code Architecture

### Authentication System
- hash_pin(): Securely hashes PIN using SHA-256
- setup_pin(): First-time PIN creation interface
- verify_pin(): PIN verification with attempt tracking
- authenticate(): Main authentication flow

### Password Operations
- save(): Add new password entries
- update(): Modify existing entries
- delete_entry(): Remove entries with confirmation
- view(): Display all stored passwords
- export_to_excel(): Create Excel backup

### Encryption
- Uses Fernet symmetric encryption from the cryptography library
- Encryption key stored in key.key
- All passwords encrypted before database storage

## Limitations
- Single-user application (no multi-user support)
- No cloud sync capability
- No password strength checker
- No password generator included
- Local storage only
  

## License
This project is open source and available for personal use.

## Disclaimer
This password manager is for educational purposes. For production use, consider established password managers with additional security features like two-factor authentication and regular security audits.

## Contributing
Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

