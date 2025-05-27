# config.py

import os

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or '25671e4d4ab0326fd3806fb84adfd9eede3f0eda7225a3f6'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
                              'postgresql://community_uy4x_user:ISdjHCL0RehKIXZtUTA8g19BSM9mwAl1@dpg-d0pkjpmuk2gs739ou2mg-a/community_uy4x'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Arkesel SMS API Configuration
    ARKESEL_API_KEY = os.environ.get('ARKESEL_API_KEY') or 'b0FrYkNNVlZGSmdrendVT3hwUHk'
    ARKESEL_SENDER_ID = 'KenyasiN1YA' # Or your registered sender ID
    # config.py

import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your_default_secret_key_if_not_in_env'
    
    # Database Configuration (for PostgreSQL)
    # Get this from your Render PostgreSQL instance's "External Database URL"
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
                              'postgresql://user:password@host:port/database_name' # REPLACE THIS WITH YOUR ACTUAL RENDER DB URL
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Arkesel SMS API Configuration
    ARKESEL_API_KEY = os.environ.get('ARKESEL_API_KEY')
    ARKESEL_SENDER_ID = os.environ.get('ARKESEL_SENDER_ID') or 'YourSenderID' # Replace with your actual sender ID