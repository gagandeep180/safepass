![safe pass ](/screenshot/project.png ) 

🔐 Secure Password Manager Suite
The Secure Password Manager Suite is a desktop application built using Python that allows users to safely store, manage, and retrieve their passwords. It is designed with security as a priority, offering PIN protection, encryption, and a user-friendly interface to manage credentials efficiently.

##  Features 
### 🔒 Security

* PIN Protection: 4-6 digit PIN authentication system
* Encryption: All passwords encrypted using Fernet (symmetric encryption)
* Secure Hashing: PINs are hashed using SHA-256 before storage
* Lockout Protection: 3 failed PIN attempts locks the application
### Password Management
- *Save*: Store new passwords with site/service name and username
- *Update*: Modify existing password entries
- *Delete*: Remove password entries with confirmation
- *View All*: Display all stored passwords in a clean format
- *Duplicate Prevention*: Warns if entry already exists


- [11:28 am, 02/01/2026] +91 87400 22105: ### 📊 Export & Backup
- *Excel Export*: Export all passwords to an XLSX file for backup
- Decrypted passwords included in export for easy access

### 🎨 User Interface
- Clean and modern GUI using Tkinter
- Color-coded buttons for different actions
- Status messages for user feedback
- Scrollable password display area
[11:29 am, 02/01/2026] +91 87400 22105: ## Installation

### Prerequisites
bash
pip install cryptography openpyxl
[11:29 am, 02/01/2026] +91 87400 22105: ### Required Packages
- tkinter (usually comes with Python)
- cryptography - For password encryption
- openpyxl - For Excel export functionality
- sqlite3 (built-in) - Database management
- hashlib (built-in) - PIN hashing
