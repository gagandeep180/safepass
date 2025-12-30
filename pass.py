import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog
from cryptography.fernet import Fernet
import sqlite3
import openpyxl
from openpyxl import Workbook
import os
import hashlib

# PIN Management
PIN_FILE = "pin.hash"

def hash_pin(pin):
    """Hash the PIN for secure storage"""
    return hashlib.sha256(pin.encode()).hexdigest()

def setup_pin():
    """First-time PIN setup"""
    pin_window = tk.Toplevel()
    pin_window.title("Setup PIN")
    pin_window.geometry("350x250")
    pin_window.resizable(False, False)
    pin_window.grab_set()
    
    # Center the window
    pin_window.update_idletasks()
    x = (pin_window.winfo_screenwidth() // 2) - (350 // 2)
    y = (pin_window.winfo_screenheight() // 2) - (250 // 2)
    pin_window.geometry(f"350x250+{x}+{y}")
    
    tk.Label(pin_window, text="Create Your PIN", font=("Arial", 16, "bold"), fg="#4CAF50").pack(pady=20)
    
    tk.Label(pin_window, text="Enter 4-6 digit PIN:", font=("Arial", 11)).pack(pady=(10, 5))
    pin_entry = tk.Entry(pin_window, show="●", font=("Arial", 16), width=12, justify="center", bd=2, relief="solid")
    pin_entry.pack(pady=5)
    pin_entry.focus()
    
    tk.Label(pin_window, text="Confirm PIN:", font=("Arial", 11)).pack(pady=(15, 5))
    confirm_entry = tk.Entry(pin_window, show="●", font=("Arial", 16), width=12, justify="center", bd=2, relief="solid")
    confirm_entry.pack(pady=5)
    
    result = {"success": False}
    
    def save_pin():
        pin = pin_entry.get().strip()
        confirm = confirm_entry.get().strip()
        
        if not pin or not confirm:
            messagebox.showerror("Error", "Please enter PIN in both fields!")
            pin_entry.focus()
            return
        
        if len(pin) < 4 or len(pin) > 6:
            messagebox.showerror("Error", "PIN must be 4-6 digits!")
            pin_entry.delete(0, tk.END)
            confirm_entry.delete(0, tk.END)
            pin_entry.focus()
            return
        
        if not pin.isdigit():
            messagebox.showerror("Error", "PIN must contain only numbers!")
            pin_entry.delete(0, tk.END)
            confirm_entry.delete(0, tk.END)
            pin_entry.focus()
            return
        
        if pin != confirm:
            messagebox.showerror("Error", "PINs do not match! Please try again.")
            confirm_entry.delete(0, tk.END)
            confirm_entry.focus()
            return
        
        # Save hashed PIN
        with open(PIN_FILE, "w") as f:
            f.write(hash_pin(pin))
        
        messagebox.showinfo("Success", "PIN created successfully!\nYour vault is now secure.")
        result["success"] = True
        pin_window.destroy()
    
    # Bind Enter key to move between fields and submit
    pin_entry.bind("<Return>", lambda e: confirm_entry.focus())
    confirm_entry.bind("<Return>", lambda e: save_pin())
    
    # Button Frame
    button_frame = tk.Frame(pin_window)
    button_frame.pack(pady=20)
    
    tk.Button(button_frame, text="✓ Create PIN", command=save_pin, bg="#4CAF50", fg="white", 
              font=("Arial", 11, "bold"), width=15, cursor="hand2").pack()
    
    pin_window.protocol("WM_DELETE_WINDOW", lambda: (messagebox.showwarning("Required", "You must create a PIN to continue!"), None))
    pin_window.wait_window()
    
    return result["success"]

def verify_pin():
    """Verify PIN to access the vault"""
    with open(PIN_FILE, "r") as f:
        stored_hash = f.read().strip()
    
    attempts = 3
    
    while attempts > 0:
        pin_window = tk.Toplevel()
        pin_window.title("Enter PIN")
        pin_window.geometry("350x220")
        pin_window.resizable(False, False)
        pin_window.grab_set()
        
        # Center the window
        pin_window.update_idletasks()
        x = (pin_window.winfo_screenwidth() // 2) - (350 // 2)
        y = (pin_window.winfo_screenheight() // 2) - (220 // 2)
        pin_window.geometry(f"350x220+{x}+{y}")
        
        tk.Label(pin_window, text="🔒 Password Vault", font=("Arial", 16, "bold"), fg="#2196F3").pack(pady=20)
        tk.Label(pin_window, text=f"Enter your PIN", font=("Arial", 11)).pack()
        tk.Label(pin_window, text=f"({attempts} attempts remaining)", font=("Arial", 9), fg="gray").pack()
        
        pin_entry = tk.Entry(pin_window, show="●", font=("Arial", 18), width=10, justify="center", bd=2, relief="solid")
        pin_entry.pack(pady=15)
        pin_entry.focus()
        
        result = {"verified": False, "cancelled": False}
        
        def check_pin():
            pin = pin_entry.get().strip()
            
            if not pin:
                messagebox.showwarning("Empty", "Please enter your PIN!")
                return
            
            if hash_pin(pin) == stored_hash:
                result["verified"] = True
                pin_window.destroy()
            else:
                messagebox.showerror("Incorrect PIN", "Wrong PIN! Please try again.")
                pin_entry.delete(0, tk.END)
                result["verified"] = False
                pin_window.destroy()
        
        def on_cancel():
            result["cancelled"] = True
            pin_window.destroy()
        
        # Bind Enter key to submit
        pin_entry.bind("<Return>", lambda e: check_pin())
        
        button_frame = tk.Frame(pin_window)
        button_frame.pack(pady=10)
        
        tk.Button(button_frame, text="🔓 Unlock", command=check_pin, bg="#4CAF50", fg="white", 
                 font=("Arial", 11, "bold"), width=12, cursor="hand2").pack(side="left", padx=5)
        tk.Button(button_frame, text="✕ Cancel", command=on_cancel, bg="#f44336", fg="white", 
                 font=("Arial", 11, "bold"), width=12, cursor="hand2").pack(side="left", padx=5)
        
        pin_window.protocol("WM_DELETE_WINDOW", on_cancel)
        pin_window.wait_window()
        
        if result["cancelled"]:
            return False
        
        if result["verified"]:
            return True
        
        attempts -= 1
    
    messagebox.showerror("Access Denied", "Too many failed attempts!\nThe application will now close for security.")
    return False

# Check for PIN and authenticate
def authenticate():
    if not os.path.exists(PIN_FILE):
        # First time setup
        welcome_msg = "Welcome to Password Manager!\n\n" \
                     "This is your first time using the app.\n" \
                     "Please create a secure PIN to protect your passwords.\n\n" \
                     "⚠️ Remember your PIN - you'll need it to access your vault!"
        messagebox.showinfo("🔐 Welcome", welcome_msg)
        
        if not setup_pin():
            messagebox.showwarning("Setup Required", "You must create a PIN to use the Password Manager.\nExiting...")
            return False
    
    # Verify PIN
    return verify_pin()

# load key (or create if doesn't exist)
if not os.path.exists("key.key"):
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)
else:
    key = open("key.key", "rb").read()

fernet = Fernet(key)

# database
db = sqlite3.connect("vault.db")
cur = db.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS vault(site TEXT, user TEXT, pwd BLOB)")
db.commit()

# functions
def save(): 
    site = site_entry.get().strip()
    user = user_entry.get().strip()
    password = pass_entry.get()
    
    # Validate inputs
    if not site or not user or not password:
        status.config(text="❌ All fields are required!", fg="red")
        return
    
    # Check for duplicate
    cur.execute("SELECT * FROM vault WHERE site=? AND user=?", (site, user))
    existing = cur.fetchone()
    
    if existing:
        status.config(text="⚠️ Already saved! Use Update to modify.", fg="orange")
        return
    
    # Save new entry
    enc = fernet.encrypt(password.encode()) 
    cur.execute("INSERT INTO vault VALUES (?,?,?)", (site, user, enc)) 
    db.commit() 
    status.config(text="✓ Saved Successfully!", fg="green")
    
    # Clear entries
    site_entry.delete(0, tk.END)
    user_entry.delete(0, tk.END)
    pass_entry.delete(0, tk.END)
    site_entry.focus()

def update():
    site = site_entry.get().strip()
    user = user_entry.get().strip()
    password = pass_entry.get()
    
    if not site or not user or not password:
        status.config(text="❌ All fields are required!", fg="red")
        return
    
    # Check if entry exists
    cur.execute("SELECT * FROM vault WHERE site=? AND user=?", (site, user))
    existing = cur.fetchone()
    
    if not existing:
        status.config(text="❌ Entry not found! Use Save instead.", fg="red")
        return
    
    # Update existing entry
    enc = fernet.encrypt(password.encode())
    cur.execute("UPDATE vault SET pwd=? WHERE site=? AND user=?", (enc, site, user))
    db.commit()
    status.config(text="✓ Updated Successfully!", fg="green")
    
    # Clear entries
    site_entry.delete(0, tk.END)
    user_entry.delete(0, tk.END)
    pass_entry.delete(0, tk.END)
    site_entry.focus()

def view():
    output.delete("1.0", tk.END)
    cur.execute("SELECT * FROM vault")
    records = cur.fetchall()
    
    if not records:
        output.insert(tk.END, "📝 No passwords saved yet.\n\nStart by adding your first password above!")
        return
    
    output.insert(tk.END, f"{'='*40}\n")
    output.insert(tk.END, f"   YOUR SAVED PASSWORDS ({len(records)} total)\n")
    output.insert(tk.END, f"{'='*40}\n\n")
    
    for i, r in enumerate(records, 1):
        try:
            decrypted_pass = fernet.decrypt(r[2]).decode()
            output.insert(tk.END, f"[{i}] Site: {r[0]}\n")
            output.insert(tk.END, f"    User: {r[1]}\n")
            output.insert(tk.END, f"    Pass: {decrypted_pass}\n")
            output.insert(tk.END, f"{'-'*40}\n")
        except:
            output.insert(tk.END, f"[{i}] Site: {r[0]}\n")
            output.insert(tk.END, f"    User: {r[1]}\n")
            output.insert(tk.END, f"    Pass: [Decryption Error]\n")
            output.insert(tk.END, f"{'-'*40}\n")

def export_to_excel():
    cur.execute("SELECT * FROM vault")
    records = cur.fetchall()
    
    if not records:
        messagebox.showwarning("No Data", "No passwords to export!\nAdd some passwords first.")
        return
    
    # Ask user where to save
    file_path = filedialog.asksaveasfilename(
        defaultextension=".xlsx",
        filetypes=[("Excel files", "*.xlsx"), ("All files", "*.*")],
        initialfile="passwords_backup.xlsx"
    )
    
    if not file_path:
        return
    
    # Create workbook
    wb = Workbook()
    ws = wb.active
    ws.title = "Passwords"
    
    # Add headers with styling
    headers = ["Site", "Username", "Password"]
    ws.append(headers)
    
    # Add data
    for r in records:
        try:
            decrypted_pass = fernet.decrypt(r[2]).decode()
            ws.append([r[0], r[1], decrypted_pass])
        except:
            ws.append([r[0], r[1], "[Decryption Error]"])
    
    # Save file
    wb.save(file_path)
    status.config(text=f"✓ Exported to {os.path.basename(file_path)}!", fg="green")
    messagebox.showinfo("Export Successful", f"✓ {len(records)} passwords exported successfully!\n\nSaved to:\n{file_path}")

def delete_entry():
    site = site_entry.get().strip()
    user = user_entry.get().strip()
    
    if not site or not user:
        status.config(text="⚠️ Enter Site and Username to delete!", fg="orange")
        return
    
    # Confirm deletion
    confirm = messagebox.askyesno("⚠️ Confirm Delete", 
                                   f"Are you sure you want to delete this password?\n\n"
                                   f"Site: {site}\n"
                                   f"User: {user}\n\n"
                                   f"This action cannot be undone!")
    
    if confirm:
        cur.execute("DELETE FROM vault WHERE site=? AND user=?", (site, user))
        db.commit()
        
        if cur.rowcount > 0:
            status.config(text="✓ Deleted Successfully!", fg="green")
            site_entry.delete(0, tk.END)
            user_entry.delete(0, tk.END)
            pass_entry.delete(0, tk.END)
            view()  # Refresh the view
            site_entry.focus()
        else:
            status.config(text="❌ Entry not found!", fg="red")

def change_pin():
    """Change the PIN"""
    if not os.path.exists(PIN_FILE):
        messagebox.showerror("Error", "No PIN found!")
        return
    
    # Verify current PIN first
    with open(PIN_FILE, "r") as f:
        stored_hash = f.read().strip()
    
    # Create verification window
    verify_window = tk.Toplevel(root)
    verify_window.title("Verify Current PIN")
    verify_window.geometry("300x150")
    verify_window.resizable(False, False)
    verify_window.grab_set()
    
    # Center window
    verify_window.update_idletasks()
    x = (verify_window.winfo_screenwidth() // 2) - (300 // 2)
    y = (verify_window.winfo_screenheight() // 2) - (150 // 2)
    verify_window.geometry(f"300x150+{x}+{y}")
    
    tk.Label(verify_window, text="Enter Current PIN:", font=("Arial", 11, "bold")).pack(pady=20)
    old_pin_entry = tk.Entry(verify_window, show="●", font=("Arial", 14), width=12, justify="center")
    old_pin_entry.pack(pady=10)
    old_pin_entry.focus()
    
    result = {"verified": False}
    
    def verify_current():
        old_pin = old_pin_entry.get().strip()
        if not old_pin:
            messagebox.showwarning("Empty", "Please enter your current PIN!")
            return
        
        if hash_pin(old_pin) != stored_hash:
            messagebox.showerror("Incorrect", "Current PIN is incorrect!")
            old_pin_entry.delete(0, tk.END)
            return
        
        result["verified"] = True
        verify_window.destroy()
    
    old_pin_entry.bind("<Return>", lambda e: verify_current())
    tk.Button(verify_window, text="✓ Verify", command=verify_current, bg="#4CAF50", 
             fg="white", font=("Arial", 10, "bold"), width=12).pack(pady=10)
    
    verify_window.wait_window()
    
    if not result["verified"]:
        return
    
    # Setup new PIN
    if setup_pin():
        messagebox.showinfo("Success", "✓ PIN changed successfully!\n\nUse your new PIN next time you open the app.")
        status.config(text="✓ PIN changed successfully!", fg="green")

# Create root window (hidden initially)
root = tk.Tk()
root.withdraw()

# Authenticate before showing main window
if not authenticate():
    root.destroy()
    db.close()
    exit()

# Show main window after successful authentication
root.deiconify()
root.title("🔐 Password Manager Suite")
root.geometry("450x650")
root.resizable(False, False)

# Header
header_frame = tk.Frame(root, bg="#4CAF50", height=60)
header_frame.pack(fill="x")
tk.Label(header_frame, text="🔐 Secure Password Vault", font=("Arial", 18, "bold"), 
         bg="#4CAF50", fg="white").pack(pady=15)

# Input Frame
input_frame = tk.Frame(root, padx=15, pady=15)
input_frame.pack(fill="x")

tk.Label(input_frame, text="🌐 Site/Service:", font=("Arial", 10, "bold")).pack(anchor="w")
site_entry = tk.Entry(input_frame, width=40, font=("Arial", 11), bd=2, relief="solid")
site_entry.pack(pady=(0, 12))

tk.Label(input_frame, text="👤 Username/Email:", font=("Arial", 10, "bold")).pack(anchor="w")
user_entry = tk.Entry(input_frame, width=40, font=("Arial", 11), bd=2, relief="solid")
user_entry.pack(pady=(0, 12))

tk.Label(input_frame, text="🔑 Password:", font=("Arial", 10, "bold")).pack(anchor="w")
pass_entry = tk.Entry(input_frame, show="●", width=40, font=("Arial", 11), bd=2, relief="solid")
pass_entry.pack(pady=(0, 12))

# Button Frame
button_frame = tk.Frame(root, pady=5)
button_frame.pack()

tk.Button(button_frame, text="💾 Save", command=save, width=11, bg="#4CAF50", fg="white", 
         font=("Arial", 9, "bold"), cursor="hand2", bd=0, relief="flat").grid(row=0, column=0, padx=4, pady=3)
tk.Button(button_frame, text="✏️ Update", command=update, width=11, bg="#2196F3", fg="white", 
         font=("Arial", 9, "bold"), cursor="hand2", bd=0, relief="flat").grid(row=0, column=1, padx=4, pady=3)
tk.Button(button_frame, text="🗑️ Delete", command=delete_entry, width=11, bg="#f44336", fg="white", 
         font=("Arial", 9, "bold"), cursor="hand2", bd=0, relief="flat").grid(row=0, column=2, padx=4, pady=3)

tk.Button(button_frame, text="👁️ View All", command=view, width=11, bg="#FF9800", fg="white", 
         font=("Arial", 9, "bold"), cursor="hand2", bd=0, relief="flat").grid(row=1, column=0, padx=4, pady=3)
tk.Button(button_frame, text="📊 Export Excel", command=export_to_excel, width=11, bg="#9C27B0", fg="white", 
         font=("Arial", 9, "bold"), cursor="hand2", bd=0, relief="flat").grid(row=1, column=1, padx=4, pady=3)
tk.Button(button_frame, text="🔄 Change PIN", command=change_pin, width=11, bg="#607D8B", fg="white", 
         font=("Arial", 9, "bold"), cursor="hand2", bd=0, relief="flat").grid(row=1, column=2, padx=4, pady=3)

# Status Label
status = tk.Label(root, text="✅ Vault Unlocked & Ready", font=("Arial", 10, "bold"), fg="green")
status.pack(pady=8)

# Output Frame
output_frame = tk.Frame(root, padx=15, pady=5)
output_frame.pack(fill="both", expand=True)

tk.Label(output_frame, text="📋 Your Passwords:", font=("Arial", 11, "bold")).pack(anchor="w", pady=(0, 5))
output = tk.Text(output_frame, height=13, width=50, font=("Consolas", 9), wrap="word", bd=2, relief="solid")
output.pack(fill="both", expand=True)

# Scrollbar for output
scrollbar = tk.Scrollbar(output, command=output.yview)
scrollbar.pack(side="right", fill="y")
output.config(yscrollcommand=scrollbar.set)

# Auto-load passwords on startup
view()

root.mainloop()

# Close database on exit
db.close()