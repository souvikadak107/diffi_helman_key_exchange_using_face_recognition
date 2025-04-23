import os
import numpy as np
import io
from PIL import Image
import face_recognition

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ------------------------------------
# IMAGE PROCESSING & EMBEDDING FUNCTIONS
# ------------------------------------
#
def load_image(file_bytes: bytes) -> np.ndarray:
    """
    Load an image from bytes and convert it to a numpy array.
    """
    image = Image.open(io.BytesIO(file_bytes))
    return np.array(image)

def get_embedding(image: np.ndarray) -> np.ndarray:
    """
    Extract the face embedding from the image.
    Throws an error if no face is detected.
    """
    encodings = face_recognition.face_encodings(image)
    if len(encodings) == 0:
        raise ValueError("No face found in the image.")
    return encodings[0]

def calculate_hash(embedding: np.ndarray) -> str:
    """
    Calculate a deterministic hash from the face embedding.
    This hash is used internally for key generation and is not returned.
    """
    digest = hashes.Hash(hashes.SHA3_512(), backend=default_backend())
    digest.update(embedding.tobytes())
    return digest.finalize().hex()

# ------------------------------------
# EMBEDDING SIMILARITY CHECK FUNCTIONS
# ------------------------------------

def cosine_similarity(emb1: np.ndarray, emb2: np.ndarray) -> float:
    dot_product = np.dot(emb1, emb2)
    norm1 = np.linalg.norm(emb1)
    norm2 = np.linalg.norm(emb2)
    return dot_product / (norm1 * norm2)

def euclidean_distance(emb1: np.ndarray, emb2: np.ndarray) -> float:
    return np.linalg.norm(emb1 - emb2)

# Strict thresholds (tune these based on your testing)
COSINE_SIMILARITY_THRESHOLD = 0.90
EUCLIDEAN_DISTANCE_THRESHOLD = 0.6

def is_matching(embedding_new: np.ndarray, embedding_base: np.ndarray) -> bool:
    """
    Returns True only if both cosine similarity and Euclidean distance
    are within strict thresholds.
    """
    cos_sim = cosine_similarity(embedding_new, embedding_base)
    euc_dist = euclidean_distance(embedding_new, embedding_base)
    print(f"Cosine similarity: {cos_sim}, Euclidean distance: {euc_dist}")
    return cos_sim >= COSINE_SIMILARITY_THRESHOLD and euc_dist <= EUCLIDEAN_DISTANCE_THRESHOLD

# ------------------------------------
# TTP & DETERMINISTIC KEY GENERATION FUNCTIONS
# ------------------------------------

def derive_master_secret(passphrase: str, salt: bytes) -> bytes:
    """
    Derives a master secret using PBKDF2 with HMAC-SHA256.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(passphrase.encode())

# Instead of hard-coding, we derive the TTP master secret.
TTP_PASSPHRASE = "YourStrongTTPPassphrase"  # Keep secret!
TTP_SALT = b"unique_ttp_salt"              # Unique & secure.

def get_ttp_master_secret() -> bytes:
    return derive_master_secret(TTP_PASSPHRASE, TTP_SALT)

def generate_deterministic_private_key(canonical_hash: str) -> ec.EllipticCurvePrivateKey:
    """
    Uses HKDF with the derived master secret and the canonical_hash as context
    to derive a 32-byte seed that is then used to produce a deterministic
    private key on the SECP256R1 curve.
    """
    master_secret = get_ttp_master_secret()
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=canonical_hash.encode(),
        backend=default_backend()
    )
    seed = hkdf.derive(master_secret)
    seed_int = int.from_bytes(seed, "big")
    
    curve = ec.SECP256R1()
    curve_order = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
    seed_int = seed_int % curve_order
    private_key = ec.derive_private_key(seed_int, curve, default_backend())
    return private_key

def simulate_ttp_generate_ibe_key(canonical_hash: str) -> (str, str):
    """
    Simulates the TTP's generation of a key pair (private & public).
    The canonical hash is used solely as input; it is not returned.
    Returns a tuple of (private_key_pem, public_key_pem).
    """
    private_key = generate_deterministic_private_key(canonical_hash)
    public_key = private_key.public_key()
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()  # Client will encrypt it.
    ).decode()
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    
    return private_pem, public_pem

# ------------------------------------
# ENCRYPTION FUNCTIONS FOR PRIVATE KEY
# ------------------------------------

def derive_encryption_key(password: str, salt: bytes) -> bytes:
    """
    Derives a symmetric encryption key from the given password and salt
    using PBKDF2-HMAC-SHA256.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_private_key(private_key_pem: str, password: str) -> (bytes, bytes):
    """
    Encrypts the given private key (in PEM format) using a key derived from the password.
    Uses AES-GCM for encryption.
    
    Returns a tuple (encrypted_data, salt), where 'salt' is used for key derivation.
    """
    salt = os.urandom(16)
    key = derive_encryption_key(password, salt)
    
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 12-byte nonce for AES-GCM.
    encrypted_data = aesgcm.encrypt(nonce, private_key_pem.encode(), None)
    
    # Concatenate nonce with encrypted data for transport.
    return nonce + encrypted_data, salt
