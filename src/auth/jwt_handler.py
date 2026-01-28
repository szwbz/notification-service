#!/usr/bin/env python3
"""
JWT Handler for authentication tokens.
Handles token creation, validation, and expiration.
"""

import os
import jwt
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

# Token expiration time in minutes
TOKEN_EXPIRY_MINUTES = 30

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "default-secret-key-change-in-production")
ALGORITHM = "HS256"


class JWTManager:
    """Manager for JWT token operations."""
    
    @staticmethod
    def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """
        Create a JWT access token.
        
        Args:
            data: Dictionary containing user data to encode
            expires_delta: Optional timedelta for token expiration
            
        Returns:
            Encoded JWT token string
        """
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRY_MINUTES)
            
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt
    
    @staticmethod
    def verify_token(token: str) -> Optional[Dict[str, Any]]:
        """
        Verify and decode a JWT token.
        
        Args:
            token: JWT token string to verify
            
        Returns:
            Decoded token payload if valid, None otherwise
        """
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            return payload
        except jwt.ExpiredSignatureError:
            print("Token has expired")
            return None
        except jwt.InvalidTokenError:
            print("Invalid token")
            return None
    
    @staticmethod
    def get_token_expiry_minutes() -> int:
        """Get the configured token expiry time in minutes."""
        return TOKEN_EXPIRY_MINUTES