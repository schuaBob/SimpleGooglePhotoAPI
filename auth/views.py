from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
import json
from google.oauth2 import id_token
from google.auth.transport import requests
from google.oauth2 import credentials
from authlib.integrations.requests_client import OAuth2Session
from google.auth.exceptions import RefreshError
# from google_auth_oauthlib.flow import Flow

class auth(APIView):
    def get(self, request):
        num = 1
        return Response(num)

    def post(self, request):
        data = request.data
        print(data)
        # 驗證idToken
        try:
            with open('credentials.json', encoding='utf-8') as f:
                appSecret = json.load(f).get('web')
                print(appSecret)
            idinfo = id_token.verify_oauth2_token(
                data.get('idToken'), requests.Request(), appSecret.get('client_id'))
            if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
                raise ValueError('Wrong issuer.')
        except ValueError:
            return Response("Wrong idToken", status=status.HTTP_403_FORBIDDEN)
        print("all good")
        # flow = Flow.from_client_secrets_file('credentials.json',scopes=data.get('scopes'),redirect_uri="http://localhost:3000/oauth/callback")
        # flow.fetch_token(code=data.get('serverAuthCode'))
        # session=flow.authorized_session()
        # print(session.get('https://photoslibrary.googleapis.com/v1/albums').json())
        # from https://requests-oauthlib.readthedocs.io/en/latest/oauth2_workflow.html#backend-application-flow
        oauth = OAuth2Session(
            client_id=appSecret.get('client_id'),
            client_secret=appSecret.get('client_secret'),
            scope=data.get('scopes')
        )
        print("all good2")
        # get https://developers.google.com/identity/protocols/oauth2/openid-connect#exchangecode
        tokens = oauth.fetch_token(url=appSecret.get('token_uri'),grant_type="authorization_code",code=data.get('serverAuthCode'),redirect_uri="http://localhost:3000/oauth/callback")
        print(tokens)
        credent = credentials.Credentials(tokens.get('access_token'),refresh_token=tokens.get('refresh_token'),token_uri=appSecret.get('token_uri'),client_id=appSecret.get('client_id'),client_secret=appSecret.get('client_secret'))

        # try:
        #     credent.refresh(requests.Request())
        # except RefreshError:
        #     print("refresh error")
        session = requests.AuthorizedSession(credent)
        res = session.get('https://photoslibrary.googleapis.com/v1/albums').json()
        print(res)
        return Response(1)
