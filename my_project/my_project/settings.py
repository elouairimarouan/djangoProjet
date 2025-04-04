"""
Django settings for my_project project.

Generated by 'django-admin startproject' using Django 5.1.7.

For more information on this file, see
https://docs.djangoproject.com/en/5.1/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/5.1/ref/settings/
"""

from pathlib import Path
import pymysql
pymysql.install_as_MySQLdb()

import cloudinary
import cloudinary.uploader
import cloudinary.api

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-1=t#9xkchz#!jq_5$%8hm!ql@g#j=%%@x_i8p9h&h5nx@1!a1h'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

import os

cloudinary.config(
    cloud_name='dvq9wue5g',  # Your Cloudinary cloud name
    api_key='584599663442754',        # Your Cloudinary API key
    api_secret='0YdznjimfTPhdjVuOnQCu4CYMO4',  # Your Cloudinary API secret
    secure=True
)
DEFAULT_FILE_STORAGE = 'cloudinary_storage.storage.MediaCloudinaryStorage'


ALLOWED_HOSTS = [ 
    'localhost',  
    '127.0.0.1',  
    "4845-105-158-105-102.ngrok-free.app",
]

CORS_ALLOWED_ORIGINS = [
    "http://localhost:5173", 
    "https://4845-105-158-105-102.ngrok-free.app"
]

CORS_ALLOW_HEADERS = [
    'content-type',
    'authorization',
    'x-custom-header',
    'ngrok-skip-browser-warning',
]

CORS_ALLOW_CREDENTIALS = True  

CSRF_TRUSTED_ORIGINS = [
    "http://localhost:5173",
    "https://4845-105-158-105-102.ngrok-free.app"
]


from datetime import timedelta

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=60),  
    'REFRESH_TOKEN_LIFETIME': timedelta(days=365),  
    'ROTATE_REFRESH_TOKENS': False,  
    'BLACKLIST_AFTER_ROTATION': False,  
    'AUTH_HEADER_TYPES': ('Bearer',),
    'SIGNING_KEY': 'signing_key', 
}

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'apis',
    'rest_framework.authtoken', 
    'rest_framework_simplejwt',
    'corsheaders',
    'channels',
    'cloudinary_storage',
    'cloudinary'
]

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',  # Only for views that require authentication
    ],
    'DEFAULT_PERMISSION_CLASSES': [
         'rest_framework.permissions.AllowAny',  # This allows public access by default
        # 'rest_framework.permissions.IsAuthenticated',

    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 6  # Adjust the page size as needed
}

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    # Remove or comment out CSRF middleware for API usage
    'django.middleware.csrf.CsrfViewMiddleware',
    'corsheaders.middleware.CorsMiddleware', 

]


FRONTEND_URL = "http://localhost:5173/"


CORS_ALLOW_ALL_ORIGINS = True 
APPEND_SLASH = False



ROOT_URLCONF = 'my_project.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

ASGI_APPLICATION = 'my_project.asgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'dbdjango',
        'USER': 'root',
        'PASSWORD': '',
        'HOST': 'localhost',
        'PORT': '3306',
    }
}

EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'  # Use SMTP to send emails
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'pcmarwan0128@gmail.com'  # Replace with your Gmail address
EMAIL_HOST_PASSWORD = 'qacj xlle mvox xzwh'

AUTH_USER_MODEL = 'apis.User'  






# Password validation
# https://docs.djangoproject.com/en/5.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.1/howto/static-files/

import os

STATIC_URL = 'static/'
MEDIA_URL = '/media/'  # URL for accessing media files
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

# Default primary key field type
# https://docs.djangoproject.com/en/5.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
 