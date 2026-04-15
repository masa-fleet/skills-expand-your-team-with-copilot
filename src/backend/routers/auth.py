"""
Authentication endpoints for the High School Management System API
"""

from fastapi import APIRouter, HTTPException
from typing import Dict, Any
import hashlib
import hmac
import os

from ..database import teachers_collection

router = APIRouter(
    prefix="/auth",
    tags=["auth"]
)

PBKDF2_ITERATIONS = 310000
SALT_SIZE = 16

def hash_password(password):
    """Hash password using PBKDF2-HMAC-SHA256 with a per-password salt."""
    salt = os.urandom(SALT_SIZE)
    derived_key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS
    )
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${derived_key.hex()}"

def verify_password(username: str, password: str, stored_password_hash: str) -> bool:
    """Verify password against stored hash (PBKDF2 format, with legacy SHA-256 migration)."""
    if stored_password_hash.startswith("pbkdf2_sha256$"):
        try:
            _, iterations, salt_hex, expected_hex = stored_password_hash.split("$", 3)
            derived_key = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode("utf-8"),
                bytes.fromhex(salt_hex),
                int(iterations)
            )
            return hmac.compare_digest(derived_key.hex(), expected_hex)
        except (ValueError, TypeError):
            return False

    # Backward compatibility for legacy unsalted SHA-256 hashes already stored.
    # If a legacy hash matches, migrate it to PBKDF2 immediately.
    legacy_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
    if hmac.compare_digest(legacy_hash, stored_password_hash):
        new_hash = hash_password(password)
        teachers_collection.update_one({"_id": username}, {"$set": {"password": new_hash}})
        return True
    return False

@router.post("/login")
def login(username: str, password: str) -> Dict[str, Any]:
    """Login a teacher account"""
    # Find the teacher in the database
    teacher = teachers_collection.find_one({"_id": username})
    
    if not teacher or not verify_password(username, password, teacher["password"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    # Return teacher information (excluding password)
    return {
        "username": teacher["username"],
        "display_name": teacher["display_name"],
        "role": teacher["role"]
    }

@router.get("/check-session")
def check_session(username: str) -> Dict[str, Any]:
    """Check if a session is valid by username"""
    teacher = teachers_collection.find_one({"_id": username})
    
    if not teacher:
        raise HTTPException(status_code=404, detail="Teacher not found")
    
    return {
        "username": teacher["username"],
        "display_name": teacher["display_name"],
        "role": teacher["role"]
    }