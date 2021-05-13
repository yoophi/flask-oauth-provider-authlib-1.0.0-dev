from authlib.integrations.flask_oauth2 import AuthorizationServer
from authlib.oauth2 import ResourceProtector
from authlib.oauth2.rfc6749 import ImplicitGrant

from app.database import db
from app.grant import AuthorizationCodeGrant, HybridGrant, OpenIDCode
from app.models import OAuth2Client, OAuth2Token


def query_client(client_id):
    return OAuth2Client.query.filter_by(client_id=client_id).first()


def save_token(token_data, request):
    if request.user:
        user_id = request.user.get_user_id()
    else:
        # client_credentials grant_type
        user_id = request.client.user_id
        # or, depending on how you treat client_credentials
        user_id = None
    token = OAuth2Token(
        client_id=request.client.client_id,
        user_id=user_id,
        **token_data
    )
    db.session.add(token)
    db.session.commit()


# or with the helper
from authlib.integrations.sqla_oauth2 import (
    create_bearer_token_validator
)

# query_client = create_query_client_func(db.session, Client)
# save_token = create_save_token_func(db.session, Token)

authorization = AuthorizationServer()
require_oauth = ResourceProtector()


def config_oauth(app):
    # query_client = create_query_client_func(db.session, OAuth2Client)
    # save_token = create_save_token_func(db.session, OAuth2Token)
    authorization.init_app(
        app,
        query_client=query_client,
        save_token=save_token
    )

    # support all openid grants
    authorization.register_grant(AuthorizationCodeGrant, [
        OpenIDCode(require_nonce=True),
    ])
    authorization.register_grant(ImplicitGrant)
    authorization.register_grant(HybridGrant)

    # protect resource
    bearer_cls = create_bearer_token_validator(db.session, OAuth2Token)
    require_oauth.register_token_validator(bearer_cls())
