import tkinter
from tkinter import messagebox
import base64

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i%len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

def kaydet_ve_sifrele():
    title = entry1.get()
    message = text1.get("1.0", tkinter.END)
    master_secret = entry2.get()
    
    if len(title) == 0 or len(message) == 0 or len(master_secret) == 0:
        messagebox.showinfo(title="Hata!!", message="Lütfen tüm alanları doldurunuz.")
    else:        
        message_encrypted = encode(master_secret, message)
        
        with open("mysecret.txt", "a") as data_file:
            data_file.write(f"\n{title}\n{message_encrypted}")
        entry1.delete(0, tkinter.END)
        entry2.delete(0, tkinter.END)
        text1.delete("1.0", tkinter.END)
        
def sifreyi_coz():
    message_encrypted = text1.get("1.0", tkinter.END)
    master_secret = entry2.get()
    
    if len(message_encrypted) == 0 or len(master_secret) == 0:
        messagebox.showinfo(title="Hata!!" , message="Lütfen gerekli alanları doldurunuz.")
    else:
        try:
            decrypted_message = decode(master_secret, message_encrypted)
        
            text1.delete("1.0", tkinter.END)
            text1.insert("1.0", decrypted_message)
        except:
            messagebox.showinfo(title="Hata!!", message="Notunuz zaten decode edildi !")


FONT = ('Verdana ',15,"bold")
window = tkinter.Tk()
window.title("Secret Notes")
window.config(padx=30, pady=30)

resim = tkinter.PhotoImage(file="indir.png")
resim_etiketi = tkinter.Label(image=resim, width=150, height=200)
resim_etiketi.pack()

label1 = tkinter.Label(text="Notunuzun başlığını giriniz: ", font=FONT)
label1.pack()

entry1 = tkinter.Entry(width=20)
entry1.pack()

label2 = tkinter.Label(text="Notunuzun giriniz: ", font=FONT)
label2.pack()

text1 = tkinter.Text(width=30, height=10)
text1.pack()

label3 = tkinter.Label(text="Notunuzun şifresini giriniz: ", font=FONT)
label3.pack()

entry2 = tkinter.Entry(width=20)
entry2.pack()

save = tkinter.Button(text="Kaydet & Şifrele", command=kaydet_ve_sifrele)
save.pack()

decrypt = tkinter.Button(text="Şifreyi Çöz", command=sifreyi_coz)
decrypt.pack()

window.mainloop()
