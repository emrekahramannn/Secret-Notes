# import 
import tkinter
from tkinter import messagebox
# from PIL import ImageTk, Image
# from cryptography.fernet import Fernet
import base64

# Screen
screen = tkinter.Tk()
screen.title("Secret Notes")
screen.minsize(width=400, height=600)
screen.maxsize(width=400, height=600)
screen.config(bg="white", pady=8)

# Photo (First Alternative Using Pillow Lib)
"""
image1 = Image.open(r"C:/Users/Emre/Desktop/Python_Bootcamp/PythonProjects/Tkinter/Encryption/top-secret.png")
img = ImageTk.PhotoImage(image1)
label1 = tkinter.Label(image=img)
label1.image = img
label1.pack()
"""

# Second Alternative Using Tkinter Directly
photo = tkinter.PhotoImage(file="top-secret.png")
photo_label = tkinter.Label(image=photo)
photo_label.pack()

FONT = ("Times New Roman", 12, "bold")

# Entry Name
title_label = tkinter.Label(text="Enter Your Title")
title_label.config(fg="black", bg="white", pady=12, font=FONT)
title_input = tkinter.Entry(width=30)
title_label.pack()
title_input.pack()

# Text (to encode and decode)
text_label = tkinter.Label(text="Enter Your Secret")
text_label.config(fg="black", bg="white", pady=12, font=FONT)
text_input = tkinter.Text(width=35, height=10)
text_label.pack()
text_input.pack()

# Key Info
key_label = tkinter.Label(text="Enter Master Key")
key_label.config(fg="black", bg="white", pady=8, font=FONT)
key_input = tkinter.Entry(width=30)
key_label.pack()
key_input.pack()


# Functions 
# ENCRYPTION FUNCS
def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def encryption():
    title = title_input.get()
    text_info = text_input.get("1.0", tkinter.END)
    key = key_input.get()

    if title.strip() == "":
        messagebox.showerror(title="Title Error", message="Please enter title.")
    elif text_info.strip() == "":
        messagebox.showerror(title="Text Error", message="Please enter text.")
    elif key.strip() == "":
        messagebox.showerror(title="Key Error", message="Please enter key")
    # before write on file learn how to encrypt
    else:
        # encryption
        encrypted_message = encode(key, text_info)
        try:
            with open("mysecret.txt", mode="a") as fhandle:
                fhandle.write(f"{title}\n{encrypted_message}\n")
        except FileNotFoundError:
            # messagebox.showerror(title="File Not Found", message="File Not Found")
            with open("mysecret.txt", "w") as fhandle:
                fhandle.write(f"{title}\n{encrypted_message}\n")
        finally:
            # after we wrote and save infos clear the screen
            title_input.delete(0, tkinter.END)
            text_input.delete("1.0", tkinter.END)
            key_input.delete(0, tkinter.END)


# DECRYPTION FUNCS
def decode(key,enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

def decryption():
    # if user gave correct encrypted message and its key
    # this function returns decrypted version of that message
    message_encrypted = text_input.get("1.0", tkinter.END)
    key = key_input.get()

    if message_encrypted.strip() == "" or key.strip() == "":
        messagebox.showerror(title="Message Or Key Error", message="Please enter a valid message and key!")
    else:
        try:
            decrypted_message = decode(key, message_encrypted)
            text_input.delete("1.0", tkinter.END)
            text_input.insert("1.0", decrypted_message)
        except:
            messagebox.showerror(title="Error!", message="Please enter encrypted text!")

# Button 
# Button 1 -Encrypt
encrypt_btn = tkinter.Button(text="Save & Encrypt", command=encryption)
encrypt_btn.config(pady=8)
encrypt_btn.pack()

# Button 2 -Decrypt
decrypt_btn = tkinter.Button(text="Decrypt", command=decryption)
decrypt_btn.config(pady=4)
decrypt_btn.pack()


screen.mainloop()