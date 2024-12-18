#!/usr/bin/env python3
""" Module of session authentication views
"""
from os import getenv
from api.v1.views import app_views
from flask import jsonify, request, make_response, abort
from models.user import User


@app_views.route("/auth_session/login", methods=["POST"], strict_slashes=False)
def login():
    """POST /api/v1/auth_session/login"""
    email = request.form.get("email", "")
    if email == "":
        return make_response(jsonify({"error": "email missing"}), 400)

    password = request.form.get("password", "")
    if password == "":
        return make_response(jsonify({"error": "password missing"}), 400)

    user = (User.search({"email": email}) + [None]).pop(0)
    if user is None:
        return make_response(
            jsonify({"error": "no user found for this email"}), 404
        )

    if not user.is_valid_password(password):
        return make_response(jsonify({"error": "wrong password"}), 401)

    from api.v1.app import auth

    session_id = auth.create_session(user.id)

    response = make_response(jsonify(user.to_json()), 200)
    response.set_cookie(getenv("SESSION_NAME"), session_id)

    return response


@app_views.route(
    "/auth_session/logout", methods=["DELETE"], strict_slashes=False
)
def logout():
    """DELETE /api/v1/auth_session/logout"""
    from api.v1.app import auth

    if not auth.destroy_session(request):
        abort(404)

    return make_response(jsonify({}), 200)
