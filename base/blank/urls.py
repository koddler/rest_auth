from django.urls import include, path
from rest_framework import routers

from .views import LoginView, RegistrationView, UserViewSet

router = routers.DefaultRouter()
router.register('user', UserViewSet)

urlpatterns = [
    path('api/', include(router.urls)),
    path('login/', LoginView.as_view()),
    path('register/', RegistrationView.as_view())
]
