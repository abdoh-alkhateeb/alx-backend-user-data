#!/usr/bin/env python3
"""
Basic auth module for the API
"""
import base64
import binascii
from typing import TypeVar
from api.v1.auth.auth import Auth
from models.user import User


class BasicAuth(Auth):
    """
    Basic auth
    """

    def extract_base64_authorization_header(
        self, authorization_header: str
    ) -> str:
        """
        Extracts base64 part
        """
        if authorization_header is None:
            return None

        if not isinstance(authorization_header, str):
            return None

        if not authorization_header.startswith("Basic "):
            return None

        return authorization_header[6:]

    def decode_base64_authorization_header(
        self, base64_authorization_header: str
    ) -> str:
        """
        Decodes base64 part
        """
        if base64_authorization_header is None:
            return None

        if not isinstance(base64_authorization_header, str):
            return None

        try:
            return base64.standard_b64decode(
                base64_authorization_header
            ).decode("utf-8")
        except binascii.Error:
            return None

    def extract_user_credentials(
        self, decoded_base64_authorization_header: str
    ) -> (str, str):
        """
        Extracts user credentials
        """
        if decoded_base64_authorization_header is None:
            return None, None

        if not isinstance(decoded_base64_authorization_header, str):
            return None, None

        if ":" not in decoded_base64_authorization_header:
            return None, None

        return tuple(decoded_base64_authorization_header.split(":"))

    def user_object_from_credentials(
        self, user_email: str, user_pwd: str
    ) -> TypeVar("User"):
        """
        Gets user object from credentials
        """
        if type(user_email) != str or type(user_pwd) != str:
            return None

        try:
            users = User.search({"email": user_email})
        except Exception:
            return None

        if len(users) <= 0:
            return None

        if users[0].is_valid_password(user_pwd):
            return users[0]

        return None

    def current_user(self, request=None) -> TypeVar("User"):
        """
        Gets current user
        """
        auth_h = self.authorization_header(request)
        b64 = self.extract_base64_authorization_header(auth_h)
        d_b64 = self.decode_base64_authorization_header(b64)
        creds = self.extract_user_credentials(d_b64)
        user = self.user_object_from_credentials(*creds)
        return user
