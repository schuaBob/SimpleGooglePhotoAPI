from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
import json
from google.oauth2 import id_token
from google.auth.transport import requests
from google.oauth2 import credentials
from authlib.integrations.requests_client import OAuth2Session
from google.auth.exceptions import RefreshError
from operator import itemgetter
from .models import User
from .serializer import UserSerializer
import datetime
import time
import io
from rest_framework.parsers import JSONParser


class auth(APIView):
    def get(self, request):
        res = {'data': 1, 'hello': 'world'}
        return Response(res, status=status.HTTP_200_OK)

    def post(self, request):
        data = request.data
        print(data)
        # check csrf
        if not request.headers.get('X-Requested-With') and request.headers.get('X-Requested-With') != "com.rnexparea":
            return Response("CSRF", status=status.HTTP_403_FORBIDDEN)
        # 驗證idToken
        try:
            with open('credentials.json', encoding='utf-8') as f:
                appSecret = json.load(f).get('web')
            print(appSecret)
            CLIENT_ID, CLIENT_SECRET, TOKEN_URI = itemgetter(
                "client_id", "client_secret", "token_uri")(appSecret)
            idinfo = id_token.verify_oauth2_token(
                data['idToken'], requests.Request(), CLIENT_ID)
            print(idinfo)
            if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
                raise ValueError('Wrong issuer')
        except ValueError:
            return Response("Wrong idToken", status=status.HTTP_403_FORBIDDEN)
        print("simple check all good")
        # if new user then create, else find that user
        user = User.objects.filter(userId=idinfo['sub'])
        print(user)
        if not user.exists():
            print("tryed")
            # create new user
            # from https://requests-oauthlib.readthedocs.io/en/latest/oauth2_workflow.html#backend-application-flow
            oauth = OAuth2Session(
                client_id=CLIENT_ID,
                client_secret=CLIENT_SECRET,
                scope=data['scopes']
            )
            # get https://developers.google.com/identity/protocols/oauth2/openid-connect#exchangecode
            tokens = oauth.fetch_token(url=TOKEN_URI, grant_type="authorization_code",
                                       code=data['serverAuthCode'], redirect_uri="http://localhost:3000/oauth/callback")
            print(tokens)
            newUser = UserSerializer(data={'userId': idinfo['sub'],
                                           'accessToken': tokens['access_token'],
                                           'expiresIn': tokens['expires_in'],
                                           'refreshToken': tokens['refresh_token']})
            if newUser.is_valid():
                newUser.save()
                print("save successfully")
            user = User.objects.filter(userId=idinfo['sub'])
        user= user.values()[0]
        print(user)
        credent = credentials.Credentials(user['accessToken'], refresh_token=user['refreshToken'],
                                          token_uri=TOKEN_URI, client_id=CLIENT_ID, client_secret=CLIENT_SECRET)

        t = time.mktime(user['lastUpdateTime'].timetuple())+user['expiresIn']
        credent.expiry = datetime.datetime.fromtimestamp(t)
        if credent.expired:
            try:
                credent.refresh(requests.Request())
            except RefreshError:
                print("refresh error")
                return Response({"error": "refresh error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        session = requests.AuthorizedSession(credent)
        res = session.get(
            'https://photoslibrary.googleapis.com/v1/albums').json()
        # photoid =mideaRes['mediaItems'][0]['id']
        print(res)
        return Response(1)
