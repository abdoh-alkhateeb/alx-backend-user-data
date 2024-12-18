#!/usr/bin/env python3
"""
Auth module for the API
"""
import os
from typing import List, TypeVar
from flask import request


class Auth:
    """
    Authorization template
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Require auth"""
        if path is None:
            return True

        if excluded_paths is None:
            return True

        path = path.rstrip("/")
        excluded_paths = [path.rstrip("/") for path in excluded_paths]

        if path in excluded_paths:
            return False

        return True

    def authorization_header(self, request=None) -> str:
        """Authorization header"""
        if request is None:
            return None

        return request.headers.get("Authorization")

    def current_user(self, request=None) -> TypeVar("User"):
        """Current user"""
        return None

    def session_cookie(self, request=None):
        """Gets session cookie"""
        if request is None:
            return None

        return request.cookies.get(os.getenv("SESSION_NAME"))
