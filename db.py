# db.py
import sqlite3
import numpy as np

def create_connection():
    conn = sqlite3.connect('database.db', detect_types=sqlite3.PARSE_DECLTYPES)
    conn.execute("PRAGMA foreign_keys = 1")
    return conn

def create_tables(conn):
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ibe_data (
            email TEXT PRIMARY KEY,
            embedding BLOB NOT NULL,
            public_key TEXT NOT NULL,
            FOREIGN KEY(email) REFERENCES users(email) ON DELETE CASCADE
        )
    ''')
    conn.commit()

def add_user(conn, email):
    cursor = conn.cursor()
    cursor.execute('INSERT INTO users (email) VALUES (?)', (email,))

def add_ibe_data(conn, email, embedding, public_key):
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO ibe_data (email, embedding, public_key)
        VALUES (?, ?, ?)
    ''', (email, embedding, public_key))

def get_ibe_data(conn, email):
    cursor = conn.cursor()
    cursor.execute('''
        SELECT embedding, public_key FROM ibe_data WHERE email = ?
    ''', (email,))
    row = cursor.fetchone()
    return row if row is None else {'embedding': row[0], 'public_key': row[1]}
