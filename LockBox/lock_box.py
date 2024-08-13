# MrJ
# Password Locker
# 7/25/2024


import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog, font
from cryptography.fernet import Fernet
import json
import os
import hashlib

# Don't worry about this
UNRELATED_NONSENSE = 'door'


# Check if master password file exists, if not, set a master password
def set_master_password():
    master_password = simpledialog.askstring("Set Password", "\tEnter new master password:\t\t", show='*')
    confirm_password = simpledialog.askstring("Set Password", "\tConfirm new master password:\t\t", show='*')
    if master_password and master_password == confirm_password:
        hashed_password = hashlib.sha256(master_password.encode()).hexdigest()
        with open(UNRELATED_NONSENSE, 'w') as file:
            file.write(hashed_password)
        messagebox.showinfo("Success", "Master password set successfully")
        return True
    else:
        messagebox.showerror("Error", "Passwords do not match")
        return False


# Authenticate using master password
def authenticate():
    if not os.path.exists(UNRELATED_NONSENSE):
        if not set_master_password():
            return False

    master_password = simpledialog.askstring("Login", "\tEnter master password:\t\t", show='*')
    with open(UNRELATED_NONSENSE, 'r') as file:
        saved_password = file.read()
    if hashlib.sha256(master_password.encode()).hexdigest() == saved_password:
        return True
    else:
        messagebox.showerror("Error", "Incorrect master password")
        return False


# Generate or load encryption key
def load_key():
    # Generate a key if it doesn't exist
    if not os.path.exists('key.key'):
        key = Fernet.generate_key()
        with open('key.key', 'wb') as key_file:
            key_file.write(key)
    else:
        with open('key.key', 'rb') as key_file:
            key = key_file.read()
    return key


# Load passwords from file
def load_passwords_from_file(file_path, key):
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
        fernet = Fernet(key)
        decrypted_data = {k: fernet.decrypt(v.encode()).decode() for k, v in data.items()}
        return decrypted_data
    except Exception as e:
        print(f"Error loading passwords from file: {e}\nYou can only open password files you have saved.")
        return {}


# Save passwords to file
def save_passwords_to_file(passwords, file_path, key):
    try:
        fernet = Fernet(key)
        encrypted_data = {k: fernet.encrypt(v.encode()).decode() for k, v in passwords.items()}
        with open(file_path, 'w') as file:
            json.dump(encrypted_data, file)
        messagebox.showinfo("Save Passwords", "Passwords saved successfully")
    except Exception as e:
        print(f"Error saving passwords to file: {e}")
        messagebox.showerror("Error", "Failed to save passwords")


def about_click():
    messagebox.showinfo(
        "About",
        "LockBox - A Simple Password Manager\n"
        f"\tCreated by MrJ\n\t        2024©"
    )


def help_click():
    messagebox.showinfo(
        "How To Use",
        "Add passwords to LockBox by entering information below and clicking the \"Add\" button.\n\n"
        "You can save a list from the file menu or with Ctrl+S.\n\n"
        "To open a previously saved password file, use the file menu or Ctrl+O.\n\n"
        "To search for a username, use the search box. Click \"Search\" again to return to full view.\n\n"
        "You can only open password files you create.\n\n"
        "Keep your master password in a safe place, it cannot be reset.\n\n"
        "To quit, use the file menu, Ctrl+Q, or the \"X\" button."
    )


class LockBox:
    def __init__(self, root, key):
        self.root = root
        self.root.title("LockBox")
        self.key = key
        self.passwords = {}

        # Create GUI
        self.create_widgets()

        # Set startup theme
        self.change_theme('light')

        # Set startup font
        self.change_font_style("Courier New")
        self.change_font_size(12)

        # Set the window size
        self.root.geometry("1024x576")

        # Bind shortcuts
        self.root.bind_all('<Control-o>', self.open_password_file_shortcut)
        self.root.bind_all('<Control-s>', self.save_password_file_shortcut)
        self.root.bind_all('<Control-q>', self.quit)

        # Configure grid to expand rows and columns
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

    def create_widgets(self):
        # Treeview for displaying passwords
        self.tree = ttk.Treeview(
            self.root,
            columns=('Username', 'Password', 'URL'),
            show='headings'
        )
        self.tree.heading('Username', text='Username')
        self.tree.heading('Password', text='Password')
        self.tree.heading('URL', text='URL')
        self.tree.grid(row=0, column=0, columnspan=4, sticky='nsew', pady=5, padx=5)

        # Entry fields and buttons
        self.search_entry = tk.Entry(self.root, width=35)
        self.search_entry.grid(row=1, column=1, sticky='w', pady=5, padx=5)

        self.search_button = tk.Button(self.root, text="Search", command=self.search_password, width=20)
        self.search_button.grid(row=1, column=0, sticky='e', pady=5, padx=5)

        self.delete_button = tk.Button(self.root, text="Delete", command=self.delete_password, width=20)
        self.delete_button.grid(row=2, column=0, sticky='w', pady=5, padx=5)

        self.separator_label = tk.Label(
            self.root,
            text=""
        )
        self.separator_label.grid(row=2, column=2, pady=5, padx=5)

        self.username_label = tk.Label(
            self.root,
            text="Username:"
        )
        self.username_label.grid(row=3, column=0, pady=5, padx=5)

        self.username_entry = tk.Entry(
            self.root,
            width=35
        )
        self.username_entry.grid(row=3, column=1, pady=5, padx=5)

        self.password_label = tk.Label(
            self.root,
            text="Password:"
        )
        self.password_label.grid(row=4, column=0, pady=5, padx=5)

        self.password_entry = tk.Entry(
            self.root,
            width=35
        )
        self.password_entry.grid(row=4, column=1, pady=5, padx=5)

        self.url_label = tk.Label(
            self.root,
            text="URL:"
        )

        self.url_label.grid(row=5, column=0, pady=5, padx=5)

        self.url_entry = tk.Entry(
            self.root,
            width=35
        )
        self.url_entry.grid(row=5, column=1, pady=5, padx=5)

        self.add_button = tk.Button(self.root, text="Add", command=self.add_password, width=20)
        self.add_button.grid(row=6, column=0, columnspan=2, pady=5, padx=5)

        # Menu
        self.menu = tk.Menu(self.root)
        self.root.config(menu=self.menu)

        self.file_menu = tk.Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="File", menu=self.file_menu)
        self.file_menu.add_command(label="Open Password File", command=self.import_passwords, accelerator="Ctrl+O")
        self.file_menu.add_command(label="Save Password File", command=self.export_passwords, accelerator="Ctrl+S")
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Exit", command=self.root.quit, accelerator="Ctrl+Q")

        self.theme_menu = tk.Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="Themes", menu=self.theme_menu)
        self.theme_menu.add_command(label="Light Theme", command=lambda: self.change_theme('light'))
        self.theme_menu.add_command(label="Dark Theme", command=lambda: self.change_theme('dark'))

        self.format_menu = tk.Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="Format", menu=self.format_menu)

        # Font size submenu
        self.font_size_menu = tk.Menu(self.format_menu, tearoff=0)
        self.format_menu.add_cascade(label="Font Size", menu=self.font_size_menu)
        self.font_size_menu.add_command(label="Small", command=lambda: self.change_font_size(10))
        self.font_size_menu.add_command(label="Medium", command=lambda: self.change_font_size(12))
        self.font_size_menu.add_command(label="Large", command=lambda: self.change_font_size(14))

        # Font style submenu
        self.font_style_menu = tk.Menu(self.format_menu, tearoff=0)
        self.format_menu.add_cascade(label="Font Style", menu=self.font_style_menu)
        self.font_style_menu.add_command(label="Arial", command=lambda: self.change_font_style("Arial"))
        self.font_style_menu.add_command(label="Courier New", command=lambda: self.change_font_style("Courier New"))
        self.font_style_menu.add_command(label="Helvetica", command=lambda: self.change_font_style("Helvetica"))
        self.font_style_menu.add_command(
            label="Times New Roman",
            command=lambda: self.change_font_style("Times New Roman")
        )
        self.font_style_menu.add_command(label="Verdana", command=lambda: self.change_font_style("Verdana"))

        self.help_menu = tk.Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="Help", menu=self.help_menu)
        self.help_menu.add_command(label="Help", command=help_click)
        self.help_menu.add_separator()
        self.help_menu.add_command(label="About LockBox", command=about_click)

    def open_password_file_shortcut(self, event):
        self.import_passwords()

    def save_password_file_shortcut(self, event):
        self.export_passwords()

    def quit(self, event):
        self.root.quit()

    def add_password(self):
        # Obtain entry fields
        username = self.username_entry.get()
        password = self.password_entry.get()
        url = self.url_entry.get()
        # Clear entry fields
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.url_entry.delete(0, tk.END)
        if username and password and url:
            self.passwords[username] = f"{password}:{url}"
            self.tree.insert('', 'end', values=(username, password, url))

    def delete_password(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Delete Password", "No item selected")
            return

        for item in selected_item:
            username = self.tree.item(item, 'values')[0]
            if username in self.passwords:
                del self.passwords[username]
            self.tree.delete(item)

    def search_password(self):
        # Obtain search field
        query = self.search_entry.get().lower()
        # Clear search field
        self.search_entry.delete(0, tk.END)
        for item in self.tree.get_children():
            self.tree.delete(item)

        for username, password_url in self.passwords.items():
            if query in username.lower():
                password, url = password_url.split(':')
                self.tree.insert('', 'end', values=(username, password, url))

    def export_passwords(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if file_path:
            save_passwords_to_file(self.passwords, file_path, self.key)

    def import_passwords(self):
        file_path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
        if file_path:
            self.passwords = load_passwords_from_file(file_path, self.key)
            self.update_treeview()

    def update_treeview(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for username, password_url in self.passwords.items():
            password, url = password_url.split(':')
            self.tree.insert('', 'end', values=(username, password, url))

    def change_theme(self, theme):
        if theme == 'light':
            self.root.config(bg='white')
            ttk.Style().configure("Treeview", background="white", foreground="black")
            ttk.Style().map("Treeview",
                            background=[("selected", "#1E90FF")],  # Dodger Blue for background
                            foreground=[("selected", "white")]  # White text color
                            )
            self.username_entry.config(bg='white', fg='black')
            self.password_entry.config(bg='white', fg='black')
            self.url_entry.config(bg='white', fg='black')
            self.search_entry.config(bg='white', fg='black')
            self.username_label.config(bg='white', fg='black')
            self.password_label.config(bg='white', fg='black')
            self.url_label.config(bg='white', fg='black')
            self.separator_label.config(bg='white', fg='black')
            self.add_button.config(bg='white', fg='black')
            self.search_button.config(bg='white', fg='black')
            self.delete_button.config(bg='white', fg='black')
            self.menu.config(bg='white', fg='black')
        elif theme == 'dark':
            self.root.config(bg='#2e2e2e')
            ttk.Style().configure("Treeview", background="#2e2e2e", foreground="white")
            ttk.Style().map("Treeview",
                            background=[("selected", "#1E90FF")],  # Dodger Blue for background
                            foreground=[("selected", "black")]  # Black text color
                            )
            self.username_entry.config(bg='#2e2e2e', fg='white')
            self.password_entry.config(bg='#2e2e2e', fg='white')
            self.url_entry.config(bg='#2e2e2e', fg='white')
            self.search_entry.config(bg='#2e2e2e', fg='white')
            self.username_label.config(bg='#2e2e2e', fg='white')
            self.password_label.config(bg='#2e2e2e', fg='white')
            self.separator_label.config(bg='#2e2e2e', fg='white')
            self.url_label.config(bg='#2e2e2e', fg='white')
            self.add_button.config(bg='#2e2e2e', fg='white')
            self.search_button.config(bg='#2e2e2e', fg='white')
            self.delete_button.config(bg='#2e2e2e', fg='white')
            self.menu.config(bg='#2e2e2e', fg='white')

    def change_font_size(self, size):
        default_font = font.nametofont("TkDefaultFont")
        default_font.configure(size=size)
        self.username_entry.config(font=default_font)
        self.password_entry.config(font=default_font)
        self.url_entry.config(font=default_font)
        self.search_entry.config(font=default_font)
        ttk.Style().configure("Treeview", font=default_font)

    def change_font_style(self, style):
        default_font = font.nametofont("TkDefaultFont")
        default_font.configure(family=style)
        self.username_entry.config(font=default_font)
        self.password_entry.config(font=default_font)
        self.url_entry.config(font=default_font)
        self.search_entry.config(font=default_font)
        ttk.Style().configure("Treeview", font=default_font)


if __name__ == "__main__":
    if authenticate():
        key = load_key()
        root = tk.Tk()
        app = LockBox(root, key)
        root.mainloop()
