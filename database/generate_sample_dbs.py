#!/usr/bin/env python3
"""
Genera bases de datos de EJEMPLO para adjuntar al entregable:
  - database/v1_database.db  (esquema y datos como quedaría v1-insecure-clean, hashes MD5)
  - database/v2_database.db  (esquema y datos como quedaría v2-secure, hashes bcrypt)
  - Exports .sql legibles de ambas para revisión sin necesidad de abrir el .db

Estos archivos son SOLO datos de ejemplo/semilla para el laboratorio; cada
vez que se ejecutan las apps reales, ambas generan su propio database.db
en su carpeta (ver v1-insecure-clean/app.py e init_db() / v2-secure/app.py).
"""

import hashlib
import os
import sqlite3
import bcrypt

HERE = os.path.dirname(os.path.abspath(__file__))

SAMPLE_USERS = [
    ("admin", "S3cur3Adm1n!"),
    ("jgomez", "Password123"),
    ("mlopez", "Qwerty2024"),
]


def md5_hash(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


def bcrypt_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def build_v1_db():
    path = os.path.join(HERE, "v1_database.db")
    if os.path.exists(path):
        os.remove(path)
    db = sqlite3.connect(path)
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            description TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)
    for username, plain in SAMPLE_USERS:
        db.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, md5_hash(plain)),
        )
    db.execute(
        "INSERT INTO files (user_id, filename, description) VALUES (1, 'nota.txt', 'Archivo de ejemplo (admin)')"
    )
    db.execute(
        "INSERT INTO files (user_id, filename, description) VALUES (2, 'reporte.csv', 'Archivo de ejemplo (jgomez)')"
    )
    db.commit()
    with open(os.path.join(HERE, "v1_database.sql"), "w") as f:
        for line in db.iterdump():
            f.write(f"{line}\n")
    db.close()
    print(f"[+] Generado {path}")


def build_v2_db():
    path = os.path.join(HERE, "v2_database.db")
    if os.path.exists(path):
        os.remove(path)
    db = sqlite3.connect(path)
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until TEXT
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            stored_filename TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            description TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    """)
    for username, plain in SAMPLE_USERS:
        db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, bcrypt_hash(plain)),
        )
    db.execute(
        "INSERT INTO files (user_id, stored_filename, original_filename, description) "
        "VALUES (1, 'a1b2c3d4e5f6.txt', 'nota.txt', 'Archivo de ejemplo (admin)')"
    )
    db.execute(
        "INSERT INTO files (user_id, stored_filename, original_filename, description) "
        "VALUES (2, 'f6e5d4c3b2a1.csv', 'reporte.csv', 'Archivo de ejemplo (jgomez)')"
    )
    db.commit()
    with open(os.path.join(HERE, "v2_database.sql"), "w") as f:
        for line in db.iterdump():
            f.write(f"{line}\n")
    db.close()
    print(f"[+] Generado {path}")


if __name__ == "__main__":
    build_v1_db()
    build_v2_db()
    print("[+] Dumps .sql generados junto a cada .db")
    print("[!] Usuarios de ejemplo (mismas contraseñas en ambas BD para comparar hashing):")
    for u, p in SAMPLE_USERS:
        print(f"    - {u} / {p}")
