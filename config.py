# config.py

import os

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or '25671e4d4ab0326fd3806fb84adfd9eede3f0eda7225a3f6'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') 
    # or \
                            #   'sqlite:///' + os.path.join(basedir, 'instance', 'community.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Arkesel SMS API Configuration
    ARKESEL_API_KEY = os.environ.get('ARKESEL_API_KEY') or 'b0FrYkNNVlZGSmdrendVT3hwUHk'
    ARKESEL_SENDER_ID = 'KenyasiN1YA' # Or your registered sender ID