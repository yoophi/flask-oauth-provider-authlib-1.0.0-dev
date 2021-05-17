import os

OAUTH2_TOKEN_EXPIRES_IN = {
    'authorization_code': 864000,
    'implicit': 3600,
    'password': 864000,
    'client_credentials': 864000
}
SQLALCHEMY_TRACK_MODIFICATIONS = False
OAUTH2_ERROR_URIS = [
    ('invalid_client', 'https://developer.your-company.com/errors#invalid-client'),
    # other error URIs
]

OAUTH2_JWT_SECRET_KEY = os.environ.get('OAUTH2_JWT_SECRET_KEY')
OAUTH2_JWT_SECRET_ALG = os.environ.get('OAUTH2_JWT_SECRET_ALG')
OAUTH2_JWT_SECRET_ISS = os.environ.get('OAUTH2_JWT_SECRET_ISS')
OAUTH2_JWT_SECRET_EXP = int(os.environ.get('OAUTH2_JWT_SECRET_EXP', 3600))
