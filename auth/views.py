from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
import json
# Create your views here.

class index(APIView):
    def get(self, request):
        number = 1
        return Response(number)

