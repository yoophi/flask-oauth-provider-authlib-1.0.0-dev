import time

from authlib.oauth2 import OAuth2Error
from flask import request, render_template, Blueprint, session, redirect, jsonify
from werkzeug.local import LocalProxy
from werkzeug.security import gen_salt

from app.database import db
from app.models import User, OAuth2Client
from app.oauth2 import authorization


def get_user():
    if 'id' in session:
        uid = session['id']
        return db.session.query(User).get(uid)

    return None


def describe_scope(*args, **kwargs):
    return {
        'key': 'email'
    }


current_user = LocalProxy(get_user)

bp = Blueprint(__name__, 'oauth')


@bp.route('/', methods=('GET', 'POST'))
def home():
    if request.method == 'POST':
        username = request.form.get('username')
        user = User.query.filter_by(username=username).first()
        if not user:
            user = User(username=username)
            db.session.add(user)
            db.session.commit()
        session['id'] = user.id
        return redirect('/')
    user = current_user
    if user:
        clients = OAuth2Client.query.filter_by(user_id=user.id).all()
    else:
        clients = []
    return render_template('home.html', user=user, clients=clients)


def split_by_crlf(s):
    return [v for v in s.splitlines() if v]


@bp.route('/create_client', methods=('GET', 'POST'))
def create_client():
    user = current_user
    if not user:
        return redirect('/')
    if request.method == 'GET':
        return render_template('create_client.html')
    form = request.form
    client_id = gen_salt(24)
    client = OAuth2Client(client_id=client_id, user_id=user.id)
    # Mixin doesn't set the issue_at date
    client.client_id_issued_at = int(time.time())
    if client.token_endpoint_auth_method == 'none':
        client.client_secret = ''
    else:
        client.client_secret = gen_salt(48)

    client_metadata = {
        "client_name": form["client_name"],
        "client_uri": form["client_uri"],
        "grant_types": split_by_crlf(form["grant_type"]),
        "redirect_uris": split_by_crlf(form["redirect_uri"]),
        "response_types": split_by_crlf(form["response_type"]),
        "scope": form["scope"],
        "token_endpoint_auth_method": form["token_endpoint_auth_method"]
    }
    client.set_client_metadata(client_metadata)
    db.session.add(client)
    db.session.commit()
    return redirect('/')


@bp.route('/oauth/authorize', methods=['GET', 'POST'])
def authorize():
    user = current_user
    if request.method == 'GET':
        try:
            grant = authorization.get_consent_grant(end_user=user)
        except OAuth2Error as error:
            return jsonify(dict(error.get_body()))

        client = grant.client
        scope = client.get_allowed_scope(grant.request.scope)

        scopes = describe_scope(scope)  # returns [{'key': 'email', 'icon': '...'}]
        return render_template(
            'authorize.html',
            grant=grant,
            user=current_user,
            client=client,
            scopes=scopes,
        )

    if not user and 'username' in request.form:
        username = request.form.get('username')
        user = db.session.query(User).filter_by(username=username).first()

    if request.form.get('confirm'):
        grant_user = user
    else:
        grant_user = None

    return authorization.create_authorization_response(grant_user=grant_user)


@bp.route('/oauth/token', methods=['POST'])
def issue_token():
    return authorization.create_token_response()
