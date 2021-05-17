import os
from dataclasses import dataclass

from authlib.oauth2.rfc6749 import grants
from authlib.oidc.core import (
    UserInfo,
    OpenIDHybridGrant as _OpenIDHybridGrant,
    OpenIDImplicitGrant as _OpenIDImplicitGrant,
    OpenIDCode as _OpenIDCode,
)
from flask import current_app
from werkzeug.local import LocalProxy

from app.database import db
from app.models import AuthorizationCode, User, OAuth2Token


@dataclass
class JwtConfig:
    key: str
    alg: str
    iss: str
    exp: int


def get_jwt_config():
    return JwtConfig(
        key=current_app.config.get('OAUTH2_JWT_SECRET_KEY'),
        alg=current_app.config.get('OAUTH2_JWT_ALG'),
        iss=current_app.config.get('OAUTH2_JWT_ISS'),
        exp=int(current_app.config.get('OAUTH2_JWT_EXP')),
    )


# noinspection PyTypeChecker
current_jwt_config: JwtConfig = LocalProxy(get_jwt_config)


class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
    def save_authorization_code(self, code, request):
        client = request.client
        nonce = request.data.get('nonce')
        auth_code = AuthorizationCode(
            code=code,
            client_id=client.client_id,
            redirect_uri=request.redirect_uri,
            scope=request.scope,
            user_id=request.user.id,
            nonce=nonce,
        )
        db.session.add(auth_code)
        db.session.commit()
        return auth_code

    def query_authorization_code(self, code, client):
        item = db.session.query(AuthorizationCode).filter_by(code=code, client_id=client.client_id).first()
        if item and not item.is_expired():
            return item

    def delete_authorization_code(self, authorization_code):
        db.session.delete(authorization_code)
        db.session.commit()

    def authenticate_user(self, authorization_code):
        return db.session.query(User).get(authorization_code.user_id)


class PasswordGrant(grants.ResourceOwnerPasswordCredentialsGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = [
        'client_secret_basic', 'client_secret_post'
    ]

    def authenticate_user(self, username, password):
        user = db.session.query(User).filter_by(username=username).first()
        if user.check_password(password):
            return user


def exists_nonce(nonce, req):
    exists = db.session.query(AuthorizationCode).filter_by(
        client_id=req.client_id, nonce=nonce
    ).first()
    return bool(exists)


def generate_user_info(user, scope):
    return UserInfo(sub=str(user.id), name=user.username)


def read_private_key_file():
    base = os.path.dirname(__file__)
    with open(os.path.join(base, 'resources/private_key.pem'), 'r') as f:
        return f.read()


class OpenIDCode(_OpenIDCode):
    def exists_nonce(self, nonce, request):
        exists = db.session.query(AuthorizationCode).filter_by(
            client_id=request.client_id, nonce=nonce
        ).first()
        return bool(exists)

    def get_jwt_config(self, grant):
        return {
            'key': current_jwt_config.key,
            'alg': current_jwt_config.alg,
            'iss': current_jwt_config.iss,
            'exp': current_jwt_config.exp,
        }

    def generate_user_info(self, user, scope):
        user_info = UserInfo(sub=user.id, name=user.username)
        if 'email' in scope:
            user_info['email'] = 'dummy-address@email.com'
        return user_info


class RefreshTokenGrant(grants.RefreshTokenGrant):
    INCLUDE_NEW_REFRESH_TOKEN = True
    TOKEN_ENDPOINT_AUTH_METHODS = [
        'client_secret_basic', 'client_secret_post'
    ]

    def authenticate_refresh_token(self, refresh_token):
        item = db.session.query(OAuth2Token).filter_by(refresh_token=refresh_token).first()
        # define is_refresh_token_valid by yourself
        # usually, you should check if refresh token is expired and revoked
        if item and item.is_refresh_token_valid():
            return item

    def authenticate_user(self, credential):
        return db.session.query(User).get(credential.user_id)

    def revoke_old_credential(self, credential):
        credential.revoked = True
        db.session.add(credential)
        db.session.commit()


class OpenIDImplicitGrant(_OpenIDImplicitGrant):
    def exists_nonce(self, nonce, request):
        exists = db.session.query(AuthorizationCode).filter_by(
            client_id=request.client_id, nonce=nonce
        ).first()
        return bool(exists)

    def get_jwt_config(self):
        return {
            'key': current_jwt_config.key,
            'alg': current_jwt_config.alg,
            'iss': current_jwt_config.iss,
            'exp': current_jwt_config.exp,
        }

    def generate_user_info(self, user, scope):
        user_info = UserInfo(sub=user.id, name=user.name)
        if 'email' in scope:
            user_info['email'] = user.email
        return user_info


class OpenIDHybridGrant(_OpenIDHybridGrant):
    def save_authorization_code(self, code, request):
        nonce = request.data.get('nonce')
        item = AuthorizationCode(
            code=code,
            client_id=request.client.client_id,
            redirect_uri=request.redirect_uri,
            scope=request.scope,
            user_id=request.user.id,
            nonce=nonce,
        )
        db.session.add(item)
        db.session.commit()
        return code

    def exists_nonce(self, nonce, request):
        exists = db.session.query(AuthorizationCode).filter_by(
            client_id=request.client_id, nonce=nonce
        ).first()
        return bool(exists)

    def get_jwt_config(self):
        return {
            'key': current_jwt_config.key,
            'alg': current_jwt_config.alg,
            'iss': current_jwt_config.iss,
            'exp': current_jwt_config.exp,
        }

    def generate_user_info(self, user, scope):
        user_info = UserInfo(sub=user.id, name=user.name)
        if 'email' in scope:
            user_info['email'] = user.email
        return user_info
