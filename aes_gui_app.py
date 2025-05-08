import base64
import datetime
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox, filedialog

# Setup GUI window
window = ttk.Window(themename="superhero")  # Try other themes like "flatly", "darkly", etc.
window.title("AES Encrypt/Decrypt")
window.geometry("600x500")
window.resizable(False, False)

# Labels and Inputs
ttk.Label(window, text="Secret Key (16 characters):").pack(pady=(10, 0))
key_entry = ttk.Entry(window, width=40, show="*")
key_entry.pack(pady=5)

ttk.Label(window, text="Message:").pack(pady=(10, 0))
message_entry = ttk.Text(window, height=5, width=70)
message_entry.pack(pady=5)

ttk.Label(window, text="Result:").pack(pady=(10, 0))
result_box = ttk.Text(window, height=5, width=70, state="disabled")
result_box.pack(pady=5)


# Log action to file
def log_action(action_type, data):
    with open("encryption_log.txt", "a") as log_file:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_file.write(f"[{timestamp}] {action_type}: {data}\n")


# Encrypt message
def encrypt_message():
    key = key_entry.get().encode()
    message = message_entry.get("1.0", "end").strip().encode()

    if len(key) != 16:
        messagebox.showerror("Key Error", "Key must be exactly 16 characters.")
        return

    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message, AES.block_size))
    iv = base64.b64encode(cipher.iv).decode()
    ct = base64.b64encode(ct_bytes).decode()
    result = f"{iv}:{ct}"

    result_box.config(state="normal")
    result_box.delete("1.0", "end")
    result_box.insert("end", result)
    result_box.config(state="disabled")

    log_action("ENCRYPT", message.decode())


# Decrypt message
def decrypt_message():
    key = key_entry.get().encode()
    encrypted = message_entry.get("1.0", "end").strip()

    if len(key) != 16:
        messagebox.showerror("Key Error", "Key must be exactly 16 characters.")
        return

    try:
        iv_str, ct_str = encrypted.split(":")
        iv = base64.b64decode(iv_str)
        ct = base64.b64decode(ct_str)

        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size).decode()

        result_box.config(state="normal")
        result_box.delete("1.0", "end")
        result_box.insert("end", pt)
        result_box.config(state="disabled")

        log_action("DECRYPT", pt)
    except Exception as e:
        messagebox.showerror("Decryption Error", f"Could not decrypt: {str(e)}")


# Save to file
def save_to_file():
    encrypted_text = result_box.get("1.0", "end").strip()
    if not encrypted_text:
        messagebox.showinfo("Nothing to Save", "There's no encrypted text to save.")
        return
    file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                             filetypes=[("Text Files", "*.txt")])
    if file_path:
        with open(file_path, "w") as file:
            file.write(encrypted_text)
        messagebox.showinfo("Saved", f"Encrypted text saved to {file_path}")


# Buttons
button_frame = ttk.Frame(window)
button_frame.pack(pady=15)

ttk.Button(button_frame, text="Encrypt", command=encrypt_message, bootstyle="success").grid(row=0, column=0, padx=10)
ttk.Button(button_frame, text="Decrypt", command=decrypt_message, bootstyle="info").grid(row=0, column=1, padx=10)
ttk.Button(button_frame, text="Save to File", command=save_to_file, bootstyle="secondary").grid(row=0, column=2, padx=10)

# Run the app
window.mainloop()
