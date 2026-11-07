# CyberData Storage System

A small Tkinter desktop app for storing per-user encrypted notes/files locally. Built as a
learning project on password hashing and symmetric encryption with Python's `cryptography`
library.

## Features

- User registration and login with a password-strength check before accounts are created.
- Each user's password is hashed with a per-user salt (PBKDF2-HMAC-SHA256), and each user's
  files are encrypted with a Fernet key derived from their own password + salt — one user's
  key cannot decrypt another user's files.
- Upload, view, list, and delete encrypted text "files" per logged-in user.

## Running it

```bash
pip install -r requirements.txt
jupyter notebook "Data Bank final.ipynb"
```

Run all cells; the last cell opens the Tkinter main menu window.

Core auth/crypto/storage logic lives in `vault.py` and the password-strength heuristic in
`strength.py` — both are plain Python modules with unit tests, importable outside the
notebook:

```bash
python -m unittest discover tests
```

## Screenshots

<img width="431" height="410" alt="mainmenu" src="https://github.com/user-attachments/assets/9a4d04a6-4680-4f19-a535-cbbf052afec7" />
<img width="431" height="481" alt="viewfile" src="https://github.com/user-attachments/assets/ff809517-1d9e-47a3-81c8-a18f28319128" />
<img width="431" height="480" alt="customermenu" src="https://github.com/user-attachments/assets/ded3d204-7a46-438a-a0ce-b608935bb08e" />
<img width="455" height="411" alt="reading data" src="https://github.com/user-attachments/assets/d05379d0-2243-4f1d-9fa8-e7e3e0d9a144" />

## Notes / limitations

This is a learning project, not a production secrets manager:

- User records (`users.txt`) and encrypted files (`users/`) are plain local files with no
  access control beyond filesystem permissions.
- There's no password-recovery flow — losing your password means losing access to your own
  files, since the file-encryption key is derived from it.
