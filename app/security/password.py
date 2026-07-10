from pwdlib import PasswordHash
from pwdlib.hashers.bcrypt import BcryptHasher

# Initialize the PasswordHash instance with Bcrypt hasher
# For production-grade modularity, this can support multiple hashers (e.g. migrating from bcrypt to argon2)
password_hash = PasswordHash((BcryptHasher(),))


def hash_password(password: str) -> str:
    """
    Hashes a plain-text password using the configured Bcrypt hasher.
    """
    return password_hash.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    """
    Verifies a plain-text password against a stored hash.
    Returns True if the password matches, False otherwise.
    """
    try:
        return password_hash.verify(password, hashed_password)
    except Exception:
        # Prevent any internal hasher error from bubbling up as 500
        return False
