# config.py

import os

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or '25671e4d4ab0326fd3806fb84adfd9eede3f0eda7225a3f6'

    # CORRECTED LINE: Make sure it's SQLALCHEMY_DATABASE_URI (not SSQLALCHEMY_DATABASE_URI)
    # And ensure the URL contains the port number :5432
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
                              'postgresql://community_uy4x_user:ISdjHCL0RehKIXZtUTA8g19BSM9mwAl1@dpg-d0pkjpmuk2gs739ou2mg-a.oregon-postgres.render.com:5432/community_uy4x'

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Arkesel SMS API Configuration
    ARKESEL_API_KEY = os.environ.get('ARKESEL_API_KEY') or 'b0FrYkNNVlZGSmdrendVT3hwUHk'
    ARKESEL_SENDER_ID = 'KenyasiN1YA' # Or your registered sender ID