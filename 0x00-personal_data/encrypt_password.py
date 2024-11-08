#!/usr/bin/env python3

"""
Defines a bunch of encryption-related logic.
"""

import bcrypt


def hash_password(password: str) -> bytes:
    """
    Returns a salted hashed password.
    """
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Returns true if password matches the hashed password.
    """
    return bcrypt.checkpw(password.encode(), hashed_password)
