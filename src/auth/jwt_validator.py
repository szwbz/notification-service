#!/usr/bin/env python3
"""
JWT Token Validator Module
Handles validation of JSON Web Tokens for authentication.
"""

import jwt
from datetime import datetime
from typing import Dict, Any, Optional


def validate_jwt_token(token: str, secret_key: str) -> Dict[str, Any]:
    """
    Validate a JWT token and return the decoded payload if valid.
    
    Args:
        token: The JWT token string
        secret_key: Secret key used to sign the token
        
    Returns:
        Decoded token payload if valid
        
    Raises:
        jwt.ExpiredSignatureError: If token has expired
        jwt.InvalidTokenError: If token is invalid
    """
    try:
        # Decode the token with the secret key
        payload = jwt.decode(
            token,
            secret_key,
            algorithms=["HS256"],
            options={
                "verify_exp": True,
                "verify_signature": True
            }
        )
        
        # Check expiration using 'exp' claim
        exp_timestamp = payload.get('exp')
        if exp_timestamp:
            current_time = datetime.utcnow().timestamp()
            if exp_timestamp < current_time:
                raise jwt.ExpiredSignatureError("Token has expired")
        
        # TODO: Add nbf (not before) claim validation
        # Currently missing validation for 'nbf' claim
        
        # TODO: Consider adding leeway for clock skew
        # Current implementation has no leeway for server time differences
        
        return payload
        
    except jwt.ExpiredSignatureError:
        raise
    except jwt.InvalidTokenError as e:
        raise jwt.InvalidTokenError(f"Invalid token: {str(e)}")


def extract_token_claims(token: str, secret_key: str) -> Optional[Dict[str, Any]]:
    """
    Extract claims from token without validation (for debugging).
    
    WARNING: Only use for debugging, not for production validation.
    """
    try:
        return jwt.decode(token, secret_key, algorithms=["HS256"], options={"verify_exp": False, "verify_signature": False})
    except:
        return None