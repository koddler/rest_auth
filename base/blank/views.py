import json

from rest_framework import views, viewsets
from rest_framework.response import Response

from .auth import TokenBasedAuthentication, Utilities
from .models import Token, User
from .serializers import UserSerializer


class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    authentication_classes = [TokenBasedAuthentication]


class RegistrationView(views.APIView):
    def post(self, request):
        try:
            user = User.objects.get(username=request.data['username'])
        except User.DoesNotExist:
            user = User(
                username=request.data['username'],
                password=request.data['password']
            )
            user.save()

            return Response(
                json.dumps({'message': 'User created'}),
                status=200
            )

        return Response(
            json.dumps({'error': 'Username already taken'}),
            status=409
        )


class LoginView(views.APIView):
    def post(self, request):
        user = Utilities.get_user(request)
        password = request.data['password']
        is_correct_password = user.check_password(password)

        if(is_correct_password):
            token = Utilities.get_or_create_user_token(user)
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


class LogoutView(views.APIView):
    """
    1. Get token from header
    2. If token is in database, delete it
    3. else return error response
    """

    def post(self, request):
        key = Utilities.get_token_from_header(request)
        try:
            token = Token.objects.get(key=key)
        except Token.DoesNotExist:
            return Response(
                json.dumps({'error': 'Invalid credentials'}),
                status=400
            )

        token.delete()
        return Response(
            json.dumps({'message': 'Successfully logged out'}),
            status=200
        )
