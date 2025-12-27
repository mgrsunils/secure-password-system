import tkinter as tk
from tkinter import messagebox
import re
import hashlib
from cryptography.fernet import Fernet

# ------------------ CRYPTO FUNCTIONS ------------------

def check_password_strength(password):
    if len(password) < 8:
        return "Weak: Min 8 characters"
    if not re.search(r"[A-Z]", password):
        return "Weak: No uppercase"
    if not re.search(r"[a-z]", password):
        return "Weak: No lowercase"
    if not re.search(r"[0-9]", password):
        return "Weak: No digit"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return "Weak: No special char"
    return "Strong Password"

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Encryption Key (generated once)
key = Fernet.generate_key()
cipher = Fernet(key)

def encrypt_data(data):
    return cipher.encrypt(data.encode())

def decrypt_data(data):
    return cipher.decrypt(data).decode()

# ------------------ GUI FUNCTIONS ------------------

def check_strength():
    pwd = password_entry.get()
    result = check_password_strength(pwd)
    strength_label.config(text=result)

def hash_pwd():
    pwd = password_entry.get()
    if pwd == "":
        messagebox.showwarning("Error", "Enter password first")
        return
    hashed = hash_password(pwd)
    hash_output.delete(0, tk.END)
    hash_output.insert(0, hashed)

def encrypt_text():
    text = encrypt_entry.get()
    if text == "":
        messagebox.showwarning("Error", "Enter text to encrypt")
        return
    encrypted = encrypt_data(text)
    encrypted_output.delete(0, tk.END)
    encrypted_output.insert(0, encrypted.decode())

def decrypt_text():
    try:
        encrypted_text = encrypted_output.get().encode()
        decrypted = decrypt_data(encrypted_text)
        decrypt_output.delete(0, tk.END)
        decrypt_output.insert(0, decrypted)
    except:
        messagebox.showerror("Error", "Invalid encrypted data")

# ------------------ GUI DESIGN ------------------

root = tk.Tk()
root.title("Secure Password & Data Protection System")
root.geometry("820x500")
root.resizable(False, False)

title = tk.Label(root, text="Secure Password & Data Protection System",
                 font=("Arial", 16, "bold"))
title.pack(pady=10)

main_frame = tk.Frame(root)
main_frame.pack()

# -------- LEFT FRAME (PASSWORD SECURITY) --------

left_frame = tk.LabelFrame(main_frame, text="Password Security",
                           font=("Arial", 12, "bold"),
                           padx=20, pady=20)
left_frame.grid(row=0, column=0, padx=15)

tk.Label(left_frame, text="Enter Password:").pack(anchor="w")
password_entry = tk.Entry(left_frame, width=30, show="*")
password_entry.pack(pady=5)

tk.Button(left_frame, text="Check Strength", command=check_strength).pack(pady=5)
strength_label = tk.Label(left_frame, text="")
strength_label.pack()

tk.Button(left_frame, text="Hash Password", command=hash_pwd).pack(pady=10)

tk.Label(left_frame, text="Hashed Password:").pack(anchor="w")
hash_output = tk.Entry(left_frame, width=40)
hash_output.pack(pady=5)

# -------- RIGHT FRAME (ENCRYPTION / DECRYPTION) --------

right_frame = tk.LabelFrame(main_frame, text="Encryption & Decryption",
                            font=("Arial", 12, "bold"),
                            padx=20, pady=20)
right_frame.grid(row=0, column=1, padx=15)

tk.Label(right_frame, text="Text to Encrypt:").pack(anchor="w")
encrypt_entry = tk.Entry(right_frame, width=40)
encrypt_entry.pack(pady=5)

tk.Button(right_frame, text="Encrypt", command=encrypt_text).pack(pady=5)

tk.Label(right_frame, text="Encrypted Output:").pack(anchor="w")
encrypted_output = tk.Entry(right_frame, width=50)
encrypted_output.pack(pady=5)

tk.Button(right_frame, text="Decrypt", command=decrypt_text).pack(pady=5)

tk.Label(right_frame, text="Decrypted Output:").pack(anchor="w")
decrypt_output = tk.Entry(right_frame, width=40)
decrypt_output.pack(pady=5)

# ------------------ START GUI ------------------
root.mainloop()
