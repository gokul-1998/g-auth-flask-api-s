from flask import Flask, redirect, url_for, session, jsonify, request
from flask_oauthlib.client import OAuth
import requests

app = Flask(__name__)
app.secret_key = 'your_secret_key'
from sec import consumer_key, consumer_secret
oauth = OAuth(app)

google = oauth.remote_app(
    'google',
    consumer_key=consumer_key,
    consumer_secret=consumer_secret,
    request_token_params={
        'scope': 'email',
    },
    base_url='https://www.googleapis.com/oauth2/v1/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
)

# Your existing routes

@app.route('/')
def index():
    return 'Welcome to Flask Google Authentication Example!'

@app.route('/login')
def login():
    return google.authorize(callback=url_for('authorized', _external=True))

@app.route('/logout')
def logout():
    google_token = session.pop('google_token', None)
    if google_token:
        # Revoke the access token using Google's revocation endpoint
        revoke_url = 'https://accounts.google.com/o/oauth2/revoke?token={}'.format(google_token[0])
        requests.get(revoke_url)
    return 'Logged out successfully.'

@app.route('/authorize')
def authorized():
    response = google.authorized_response()
    if response is None or response.get('access_token') is None:
        return 'Access denied: reason={} error={}'.format(
            request.args['error_reason'],
            request.args['error_description']
        )

    session['google_token'] = (response['access_token'], '')
    user_info = google.get('userinfo')
    return 'Logged in as: ' + user_info.data['email']

@google.tokengetter
def get_google_oauth_token():
    return session.get('google_token')

# New routes

@app.route('/api/authorized')

def authorized_api():
    if 'google_token' not in session:
        return jsonify({'message': 'Unauthorized API'})

    user_info = google.get('userinfo')
    return jsonify({'message': 'Authorized API', 'user_email': user_info.data['email']})


@app.route('/api/unauthorized')
def unauthorized_api():
    return jsonify({'message': 'Unauthorized API'})

if __name__ == '__main__':
    app.run(debug=True)
