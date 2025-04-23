# main.py
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import JSONResponse
import utils
import db
import sqlite3
import numpy as np

app = FastAPI(title="Secure DH & IBE Demo Backend")

@app.on_event("startup")
async def initialize_database():
    conn = db.create_connection()
    db.create_tables(conn)
    conn.close()

@app.post("/register")
async def register_user(
    email: str = Form(...),
    password: str = Form(...),
    image: UploadFile = File(...)
):
    conn = None
    try:
        # Process the image
        file_bytes = await image.read()
        img_array = utils.load_image(file_bytes)
        base_embedding = utils.get_embedding(img_array)
        
        # Generate keys
        canonical_hash = utils.calculate_hash(base_embedding)
        private_pem, public_pem = utils.simulate_ttp_generate_ibe_key(canonical_hash)
        
        # Encrypt private key (returned to client, not stored)
        encrypted_private, encryption_salt = utils.encrypt_private_key(private_pem, password)
        
        # Store data in SQLite
        conn = db.create_connection()
        try:
            db.add_user(conn, email)
            embedding_bytes = base_embedding.tobytes()
            db.add_ibe_data(conn, email, embedding_bytes, public_pem)
            conn.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=400, detail="User already registered")
        finally:
            if conn:
                conn.close()
        
        return JSONResponse(content={
            "message": "Registration successful.",
            "public_key": public_pem,
            "encrypted_private_key": encrypted_private.hex(),
            "encryption_salt": encryption_salt.hex()
        })
    except Exception as e:
        if conn:
            conn.rollback()
            conn.close()
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/verify")
async def verify_user(
    email: str = Form(...),
    image: UploadFile = File(...)
):
    conn = None
    try:
        conn = db.create_connection()
        stored_data = db.get_ibe_data(conn, email)
        if not stored_data:
            raise HTTPException(status_code=400, detail="Email not registered")
        
        # Process new image
        file_bytes = await image.read()
        img_array = utils.load_image(file_bytes)
        new_embedding = utils.get_embedding(img_array)
        
        # Compare embeddings
        stored_embedding = np.frombuffer(stored_data['embedding'], dtype=np.float64)
        if utils.is_matching(new_embedding, stored_embedding):
            return JSONResponse(content={
                "message": "Image verified",
                "public_key": stored_data['public_key']
            })
        else:
            raise HTTPException(status_code=400, detail="Face mismatch")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        if conn:
            conn.close()

@app.post("/dh_exchange")
async def dh_exchange():
    return JSONResponse(content={"shared_secret": "dummy_shared_secret_value"})
