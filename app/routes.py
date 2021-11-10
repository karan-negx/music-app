# -*- coding: utf-8 -*-
from app import app, db
from app.models import LikedVideos
import os
import flask
import requests
import logging

import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery

CLIENT_SECRETS_FILE = "client_secret.json"

SCOPES = ['https://www.googleapis.com/auth/youtube.force-ssl']
API_SERVICE_NAME = 'youtube'
API_VERSION = 'v3'

@app.route('/')
@app.route('/home')
def index():
    return flask.render_template('home.html')

@app.route('/authorize')
def authorize():
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES)
    flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true')

    flask.session['state'] = state
    return flask.redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
    state = flask.session['state']

    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
    flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

    authorization_response = flask.request.url
    flow.fetch_token(authorization_response=authorization_response)

    credentials = flow.credentials
    flask.session['credentials'] = credentials_to_dict(credentials)

    return flask.render_template('home.html')

@app.route('/liked_videos/')
@app.route('/liked_videos/view')
def view_liked_videos():
    return flask.render_template('liked_videos_table.html', items = LikedVideos.query.all())

@app.route("/liked_videos/get")
def get_liked_videos():
    if 'credentials' not in flask.session:
        return flask.redirect('/authorize')
    credentials = google.oauth2.credentials.Credentials(
        **flask.session['credentials'])
    youtube = googleapiclient.discovery.build(
        API_SERVICE_NAME, API_VERSION, credentials=credentials)
    request = youtube.videos().list
    nextPageToken = False
    while True:
        if nextPageToken:
            request_ll = request(
                part="snippet,contentDetails,statistics",
                myRating="like",
                maxResults=50,
                pageToken=nextPageToken
            )
        else:
            request_ll = request(
                part="snippet,contentDetails,statistics",
                myRating="like",
                maxResults=50,
            )
        response = request_ll.execute()
        if response.get('items'):
            for item in response.get('items'):
                post = LikedVideos(yt_id=item.get('id'), name=item.get('snippet',{}).get('title'))
                db.session.add(post)
            db.session.commit()
        nextPageToken = response.get('nextPageToken')
        if not nextPageToken:
            break
        data = LikedVideos.query.all()
    return flask.render_template('liked_videos_table.html', items=data)

def parse_ll_data(response):
    return {
        'yt_id': response.get('id'),
        'title':response.get('snippet').get('title')
    }

@app.route('/revoke')
def revoke():
    if 'credentials' not in flask.session:
        return ('You need to <a href="/authorize">authorize</a> before ' +
                'testing the code to revoke credentials.')

    credentials = google.oauth2.credentials.Credentials(
        **flask.session['credentials'])

    revoke = requests.post('https://oauth2.googleapis.com/revoke',
                        params={'token': credentials.token},
                        headers={'content-type': 'application/x-www-form-urlencoded'})

    status_code = getattr(revoke, 'status_code')
    if status_code == 200:
        return('Credentials successfully revoked.' + print_index_table())
    else:
        return('An error occurred.' + print_index_table())


@app.route('/clear')
def clear_credentials():
    if 'credentials' in flask.session:
        del flask.session['credentials']
    return ('Credentials have been cleared.<br><br>' +
            print_index_table())


def credentials_to_dict(credentials):
    return {'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes}

def print_index_table():
    return ('<table>' +
            '<tr><td><a href="/test">Test an API request</a></td>' +
            '<td>Submit an API request and see a formatted JSON response. ' +
            '    Go through the authorization flow if there are no stored ' +
            '    credentials for the user.</td></tr>' +
            '<tr><td><a href="/authorize">Test the auth flow directly</a></td>' +
            '<td>Go directly to the authorization flow. If there are stored ' +
            '    credentials, you still might not be prompted to reauthorize ' +
            '    the application.</td></tr>' +
            '<tr><td><a href="/revoke">Revoke current credentials</a></td>' +
            '<td>Revoke the access token associated with the current user ' +
            '    session. After revoking credentials, if you go to the test ' +
            '    page, you should see an <code>invalid_grant</code> error.' +
            '</td></tr>' +
            '<tr><td><a href="/clear">Clear Flask session credentials</a></td>' +
            '<td>Clear the access token currently stored in the user session. ' +
            '    After clearing the token, if you <a href="/test">test the ' +
            '    API request</a> again, you should go back to the auth flow.' +
            '</td></tr></table>')


if __name__ == '__main__':
    # When running locally, disable OAuthlib's HTTPs verification.
    # ACTION ITEM for developers:
    #     When running in production *do not* leave this option enabled.
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

    # Specify a hostname and port that are set as a valid redirect URI
    # for your API project in the Google API Console.
    app.run('localhost', 5000, debug=True)
