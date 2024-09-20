import tkinter as tk
from tkinter import filedialog, messagebox
import numpy as np

# Vigenère Cipher
def vigenere_encrypt(plaintext, key):
    ciphertext = []
    key = key.upper()
    key_len = len(key)
    for i, char in enumerate(plaintext):
        if char.isalpha():
            shift = ord(key[i % key_len]) - 65
            if char.isupper():
                ciphertext.append(chr((ord(char) + shift - 65) % 26 + 65))
            else:
                ciphertext.append(chr((ord(char) + shift - 97) % 26 + 97))
        else:
            ciphertext.append(char)
    return ''.join(ciphertext)

def vigenere_decrypt(ciphertext, key):
    plaintext = []
    key = key.upper()
    key_len = len(key)
    for i, char in enumerate(ciphertext):
        if char.isalpha():
            shift = ord(key[i % key_len]) - 65
            if char.isupper():
                plaintext.append(chr((ord(char) - shift - 65) % 26 + 65))
            else:
                plaintext.append(chr((ord(char) - shift - 97) % 26 + 97))
        else:
            plaintext.append(char)
    return ''.join(plaintext)

# Playfair Cipher
def generate_playfair_matrix(key):
    matrix = []
    key = key.upper().replace("J", "I")
    used_letters = set()
    
    for char in key:
        if char not in used_letters and char.isalpha():
            used_letters.add(char)
            matrix.append(char)
    
    for char in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if char not in used_letters:
            used_letters.add(char)
            matrix.append(char)
    
    return np.array(matrix).reshape(5, 5)

def playfair_encrypt(plaintext, key):
    matrix = generate_playfair_matrix(key)
    plaintext = plaintext.upper().replace("J", "I").replace(" ", "")
    
    if len(plaintext) % 2 != 0: 
        plaintext += 'X'
    
    ciphertext = ""
    i = 0
    
    while i < len(plaintext):
        pair = plaintext[i:i+2]
        if len(pair) < 2: 
            break
        if pair[0] == pair[1]:
            pair = pair[0] + 'X'
            i -= 1 
        else:
            i += 2
        
        row1, col1 = np.where(matrix == pair[0])
        row2, col2 = np.where(matrix == pair[1])

        if row1.size == 0 or row2.size == 0: 
            break
            
        if row1[0] == row2[0]:
            ciphertext += matrix[row1[0], (col1[0] + 1) % 5] + matrix[row2[0], (col2[0] + 1) % 5]
        elif col1[0] == col2[0]:
            ciphertext += matrix[(row1[0] + 1) % 5, col1[0]] + matrix[(row2[0] + 1) % 5, col2[0]]
        else:
            ciphertext += matrix[row1[0], col2[0]] + matrix[row2[0], col1[0]]
    
    return ciphertext

def playfair_decrypt(ciphertext, key):
    matrix = generate_playfair_matrix(key)
    plaintext = ""
    ciphertext = ciphertext.upper().replace("J", "I").replace(" ", "")
    
    i = 0
    while i < len(ciphertext):
        pair = ciphertext[i:i+2]
        if len(pair) < 2: 
            break
        i += 2
        
        row1, col1 = np.where(matrix == pair[0])
        row2, col2 = np.where(matrix == pair[1])
        
        if row1.size == 0 or row2.size == 0: 
            break 

        if row1[0] == row2[0]:
            plaintext += matrix[row1[0], (col1[0] - 1) % 5] + matrix[row2[0], (col2[0] - 1) % 5]
        elif col1[0] == col2[0]:
            plaintext += matrix[(row1[0] - 1) % 5, col1[0]] + matrix[(row2[0] - 1) % 5, col2[0]]
        else:
            plaintext += matrix[row1[0], col2[0]] + matrix[row2[0], col1[0]]
    
    return plaintext.replace('X', '')

# Hill Cipher
def hill_encrypt(plaintext, key):
    key_matrix = np.array(key).reshape(2, 2)
    plaintext = plaintext.upper().replace(' ', '')
    plaintext_nums = [ord(char) - 65 for char in plaintext]
    
    if len(plaintext_nums) % 2 != 0:
        plaintext_nums.append(0)
    
    plaintext_matrix = np.array(plaintext_nums).reshape(-1, 2)
    cipher_matrix = (plaintext_matrix @ key_matrix) % 26
    ciphertext = ''.join([chr(int(num) + 65) for num in cipher_matrix.flatten()])
    return ciphertext

def hill_decrypt(ciphertext, key):
    key_matrix = np.array(key).reshape(2, 2)
    determinant = int(np.round(np.linalg.det(key_matrix))) % 26
    inv_determinant = pow(determinant, -1, 26)
    key_matrix_inv = np.round(inv_determinant * np.linalg.inv(key_matrix) * determinant).astype(int) % 26

    ciphertext_nums = [ord(char) - 65 for char in ciphertext]
    ciphertext_matrix = np.array(ciphertext_nums).reshape(-1, 2)
    plaintext_matrix = (ciphertext_matrix @ key_matrix_inv) % 26
    plaintext = ''.join([chr(int(num) + 65) for num in plaintext_matrix.flatten()])
    return plaintext

# GUI
class CipherApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Tugas Kriptografi (Enkripsi/Dekripsi)")

        # Input and Output text
        self.label_input = tk.Label(root, text="Input:")
        self.label_input.grid(row=0, column=0, padx=10, pady=5)
        self.input_text = tk.Text(root, height=10, width=40)
        self.input_text.grid(row=1, column=0, padx=10, pady=5)

        self.label_output = tk.Label(root, text="Hasil:")
        self.label_output.grid(row=0, column=1, padx=10, pady=5)
        self.output_text = tk.Text(root, height=10, width=40)
        self.output_text.grid(row=1, column=1, padx=10, pady=5)

        # Tombol upload file
        self.upload_button = tk.Button(root, text="Upload Text File", command=self.upload_file)
        self.upload_button.grid(row=2, column=0, columnspan=2, pady=5)

        # Memilih tipe enkripsi
        self.cipher_var = tk.StringVar(value="vigenere")
        self.vigenere_radio = tk.Radiobutton(root, text="Vigenere", variable=self.cipher_var, value="vigenere")
        self.playfair_radio = tk.Radiobutton(root, text="Playfair", variable=self.cipher_var, value="playfair")
        self.hill_radio = tk.Radiobutton(root, text="Hill", variable=self.cipher_var, value="hill")

        self.vigenere_radio.grid(row=3, column=0, padx=5)
        self.playfair_radio.grid(row=3, column=1, padx=5)
        self.hill_radio.grid(row=4, column=0, columnspan=3, padx=5)

        # Input kunci
        self.label_key = tk.Label(root, text="Masukkan Kunci (minimal 12 Karakter):")
        self.label_key.grid(row=5, column=0, columnspan=3, pady=5)
        self.key_entry = tk.Entry(root, width=50)
        self.key_entry.grid(row=6, column=0, columnspan=3, padx=10, pady=5)

        # Tombol enkripsi dan dekripsi
        self.encrypt_button = tk.Button(root, text="Enkripsi", command=self.encrypt)
        self.encrypt_button.grid(row=7, column=0, padx=10, pady=5)
        self.decrypt_button = tk.Button(root, text="Dekripsi", command=self.decrypt)
        self.decrypt_button.grid(row=7, column=1, padx=10, pady=5)

    def upload_file(self):
        filepath = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if filepath:
            with open(filepath, 'r') as file:
                content = file.read()
                self.input_text.delete("1.0", tk.END)
                self.input_text.insert(tk.END, content)

    def encrypt(self):
        method = self.cipher_var.get()
        key = self.key_entry.get()
        input_text = self.input_text.get("1.0", tk.END).strip()
        
        if len(key) < 12:
            messagebox.showerror("Error", "Kunci harus minimal terdiri dari 12 karakter!")
            return
        
        try:
            if method == "vigenere":
                result = vigenere_encrypt(input_text, key)
            elif method == "playfair":
                result = playfair_encrypt(input_text, key)
            elif method == "hill":
                key_matrix = [int(x) for x in key.split()]
                result = hill_encrypt(input_text, key_matrix)
            else:
                result = ""
            
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, result)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt(self):
        method = self.cipher_var.get()
        key = self.key_entry.get()
        input_text = self.input_text.get("1.0", tk.END).strip()
        
        if len(key) < 12:
            messagebox.showerror("Error", "Kunci harus minimal terdiri dari 12 karakter!")
            return
        
        try:
            if method == "vigenere":
                result = vigenere_decrypt(input_text, key)
            elif method == "playfair":
                result = playfair_decrypt(input_text, key)
            elif method == "hill":
                key_matrix = [int(x) for x in key.split()]
                result = hill_decrypt(input_text, key_matrix)
            else:
                result = ""
            
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, result)
        except Exception as e:
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = CipherApp(root)
    root.mainloop()
