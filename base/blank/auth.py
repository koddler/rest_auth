from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed

from .models import Token, User


class TokenBasedAuthentication(BaseAuthentication):
    def authenticate(self, request):
        token = Utilities.get_token(request)
        return self.get_token_user(token), None

    def get_token_user(self, token):
        t = Token.objects.get(key=token)
        user = t.user

        if user is None:
            raise AuthenticationFailed('Invalid user')

        return (user, token)


class Utilities:
    @staticmethod
    def get_token(request):
        header = get_authorization_header(request)
        if header is None:
            return None

        token = header.split()
        if len(token) == 0:
            raise AuthenticationFailed(
                'Authentication token not provided'
            )
        elif len(token) != 2:
            raise AuthenticationFailed(
                'Authentication header must contain two space separated values'
            )

        # using decode because token[1] is a bytes type data
        return token[1].decode('utf-8')

    @staticmethod
    def get_user(request):
        try:
            user = User.objects.get(username=request.data['username'])
        except User.DoesNotExist:
            raise AuthenticationFailed('User does not exist')

        return user

    @staticmethod
    def get_token_from_user(user):
        try:
            token = Token.objects.get(user_id=user.id)
        except Token.DoesNotExist:
            raise AuthenticationFailed('User not logged in')

        return token

    @staticmethod
    def get_user_from_token(token):
        pass

    @staticmethod
    def get_or_create_user_token(user):
        # if user is logged in return existing token
        # else create a new one
        try:
            token = Token.objects.get(user_id=user.id)
        except Token.DoesNotExist:
            token = Token()

        return token
