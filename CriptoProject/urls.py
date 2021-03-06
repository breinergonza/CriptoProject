"""CriptoProject URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from django.urls.conf import include

#Importar app con  las vistas
from cifradoapp import views

urlpatterns = [
    path('', views.index),
    path('index/', views.index),

    path('rsa/', views.encript_rsa),

    path('file_view/', views.file_text),
    path('file_private/', views.file_private),
    path('file_public/', views.file_public),
    path('guardar/',  views.save_file, name="save"),
    path('admin/', admin.site.urls),

    path('api/register/', views.register_view, name="register"),

    path('api/account/', include('cifradoapp.api.urls', 'account_api')),

    path('hello/', views.HelloView.as_view(), name='hello'),

    path('code/', views.CodeText.as_view(), name='code'),

    path('decode/', views.DeCodeText.as_view(), name='decode'),

    path('gKeyDsa/', views.GenerateKeysDsa.as_view(), name='gDeyRsa'),

    path('getFile/', views.SendFile.as_view(), name='getFile'),

    path('vTemp/', views.ValidateTempratureText.as_view(), name='vTemp'),

    path('codeTxt/', views.CodeTextoPlano.as_view(), name='codeTxt')
]
