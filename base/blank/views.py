import json

from rest_framework import views, viewsets
from rest_framework.response import Response

from .auth import TokenBasedAuthentication
from .models import Token, User
from .serializers import UserSerializer


class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    authentication_classes = [TokenBasedAuthentication]


class RegistrationView(views.APIView):
    def post(self, request):
        user = User(
            username=request.data['username'],
            password=request.data['password']
        )
        user.save()

        return Response(
            json.dumps({"message": "created"}),
            status=200
        )


class LoginView(views.APIView):
    def post(self, request):
        try:
            user = User.objects.get(username=request.data['username'])
        except User.DoesNotExist:
            return Response(
                json.dumps({'message': 'User does not exist'}),
                status=401
            )

        password = request.data['password']
        is_correct_password = user.check_password(password)

        if(is_correct_password):
            token = Token()
            token.user = user
            token.save()
            return Response(
                json.dumps({'token': token.key}),
                status=202
            )

        return Response(
            json.dumps({'error': 'Invalid password'}),
            status=401
        )
