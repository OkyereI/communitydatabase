# app.py

import os
import random
import string
import requests
from datetime import datetime, date 
from dotenv import load_dotenv

from flask import Flask, redirect, url_for, flash, request, render_template, Response
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin, AdminIndexView, expose
from flask_admin.contrib.sqla import ModelView
from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, TextAreaField, IntegerField, BooleanField, SubmitField, PasswordField, DateField 
from wtforms.validators import DataRequired, Length, Optional, Regexp, Email, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from sqlalchemy import func

# --- GLOBAL VARIABLES & SETUP ---
basedir = os.path.abspath(os.path.dirname(__file__))

# Ensure necessary folders exist
instance_path = os.path.join(basedir, 'instance')
os.makedirs(instance_path, exist_ok=True)
os.makedirs(os.path.join(basedir, 'templates', 'admin'), exist_ok=True) 

# Initialize Flask app
app = Flask(__name__, instance_relative_config=True)
app.config.from_object('config.Config')

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "warning"

# --- User Model for Admin Authentication ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(password, self.password_hash)

    def __repr__(self):
        return f'<User {self.username}>'

# --- Flask-Login user loader ---
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# --- CommunityMember Model ---
class CommunityMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    date_of_birth = db.Column(db.Date, nullable=False) 
    gender = db.Column(db.String(10), nullable=False)
    contact_number = db.Column(db.String(20), nullable=True)
    email = db.Column(db.String(120), unique=True, nullable=True)
    address = db.Column(db.Text, nullable=True)
    employment_status = db.Column(db.String(50), nullable=True)
    occupation = db.Column(db.String(100), nullable=True)
    employer = db.Column(db.String(100), nullable=True)
    parent_guardian_name = db.Column(db.String(200), nullable=True)
    parent_guardian_contact = db.Column(db.String(20), nullable=True)
    parent_guardian_address = db.Column(db.Text, nullable=True)
    area_code = db.Column(db.String(10), nullable=False)
    verification_code = db.Column(db.String(20), unique=True, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<CommunityMember {self.first_name} {self.last_name}>'

# --- Verification Code Generation ---
def generate_verification_code(area_code: str) -> str:
    base_string = f"KN1YA{area_code}"
    if len(base_string) >= 10:
        return base_string[:10]
    remaining_length = 10 - len(base_string)
    characters = string.ascii_uppercase + string.digits
    random_suffix = ''.join(random.choice(characters) for _ in range(remaining_length))
    return f"{base_string}{random_suffix}"

# --- SMS Sending Function (UPDATED for multi-line format) ---
def send_sms(recipient: str, message: str, verification_code: str = "", first_name: str = "", last_name: str = "") -> bool:
    print("DEBUG: Entering send_sms function. Using GET request logic.") 

    api_key = app.config['ARKESEL_API_KEY']
    sender_id = app.config['ARKESEL_SENDER_ID']
    url = "https://sms.arkesel.com/sms/api"

    if recipient: 
        recipient = recipient.strip() 
        if recipient.startswith('+'):
            recipient = recipient.lstrip('+') 
        if recipient.startswith('0'):
            recipient = '233' + recipient[1:] 
        elif not recipient.startswith('233'):
            recipient = '233' + recipient
        recipient = '+' + recipient
    else:
        app.logger.warning("Attempted to send SMS to an empty recipient number.")
        return False 

    # Construct the final message in the exact multi-line format requested
    final_message_parts = []
    
    # 1. Verification Code line
    if verification_code:
        final_message_parts.append(f"Verification code: {verification_code}")

    # 2. Name line
    full_name = f"{first_name} {last_name}".strip()
    if full_name:
        final_message_parts.append(f"Name: {full_name}")

    # 3. Separator line (only if there's header content AND a message body)
    if (verification_code or full_name) and message.strip():
        final_message_parts.append(".....................................")
    
    # 4. Admin message body
    if message.strip():
        final_message_parts.append(message.strip()) 

    # 5. Fixed footer
    final_message_parts.append("From: Kenyasi N1 Youth association")

    # Join all parts with newlines
    final_message = "\n".join(final_message_parts)

    
    payload = {
        "action": "send-sms",      
        "api_key": api_key,
        "to": recipient,           
        "from": sender_id,         
        "sms": final_message # Corrected: 'message' to 'sms'
    }

    try:
        app.logger.info(f"Attempting to send SMS to {recipient} with message: \n'{final_message}'\n using GET request.") # Added newlines for clearer logging
        response = requests.get(url, params=payload) 
        
        if not response.ok: 
            app.logger.error(f"Arkesel API returned non-success HTTP status {response.status_code}.") 
            app.logger.error(f"Arkesel Raw Response Text: {response.text}")
            try:
                error_data = response.json()
                app.logger.error(f"Arkesel Parsed Error JSON: {error_data}")
            except requests.exceptions.JSONDecodeError:
                app.logger.error("Arkesel response could not be parsed as JSON.")
            return False 

        response_data = response.json()
        if response_data.get('code') == 'ok': 
            app.logger.info(f"SMS sent successfully to {recipient}. Arkesel response: {response_data}")
            return True
        else:
            error_code = response_data.get('code', 'N/A')
            error_message = response_data.get('message', 'No specific message from Arkesel.')
            app.logger.error(f"Failed to send SMS to {recipient}. Arkesel API responded with code: '{error_code}', message: '{error_message}'. Full response: {response_data}")
            return False
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Error sending SMS to {recipient}: {e}")
        return False

# --- Flask-Admin Customization ---

class MyAdminIndexView(AdminIndexView):
    @expose('/')
    @login_required
    def index(self):
        total_members = db.session.query(CommunityMember).count()
        employment_status_stats = db.session.query(
            CommunityMember.employment_status, func.count(CommunityMember.id)
        ).group_by(CommunityMember.employment_status).all()
        employment_status_dict = {
            status if status else 'Not Specified': count 
            for status, count in employment_status_stats
        }
        gender_stats = db.session.query(
            CommunityMember.gender, func.count(CommunityMember.id)
        ).group_by(CommunityMember.gender).all()
        gender_dict = {
            gender if gender else 'Not Specified': count 
            for gender, count in gender_stats
        }
        area_code_stats = db.session.query(
            CommunityMember.area_code, func.count(CommunityMember.id)
        ).group_by(CommunityMember.area_code).order_by(func.count(CommunityMember.id).desc()).limit(5).all()
        area_code_dict = {
            code if code else 'Not Specified': count 
            for code, count in area_code_stats
        }

        stats = {
            'total_members': total_members,
            'employment_status': employment_status_dict,
            'gender': gender_dict,
            'area_code': area_code_dict,
        }
        return self.render('admin/index.html', stats=stats)

class CommunityMemberForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired(), Length(max=100)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(max=100)])
    date_of_birth = DateField('Date of Birth (YYYY-MM-DD)', format='%Y-%m-%d', validators=[DataRequired()])
    gender = SelectField('Gender', choices=[('Male', 'Male'), ('Female', 'Female'), ('Other', 'Other')], validators=[DataRequired()])
    contact_number = StringField('Contact Number', validators=[Optional(), Length(max=20)])
    email = StringField('Email', validators=[Optional(), Email(), Length(max=120)])
    address = TextAreaField('Address', validators=[Optional()])
    employment_status = SelectField('Employment Status', choices=[
        ('Employed', 'Employed'), ('Unemployed', 'Unemployed'),
        ('Student', 'Student'), ('Retired', 'Retired'), ('Other', 'Other')
    ], validators=[Optional()])
    occupation = StringField('Occupation', validators=[Optional(), Length(max=100)])
    employer = StringField('Employer', validators=[Optional(), Length(max=100)])
    parent_guardian_name = StringField('Parent/Guardian Name', validators=[Optional(), Length(max=200)])
    parent_guardian_contact = StringField('Parent/Guardian Contact', validators=[Optional(), Length(max=20)])
    parent_guardian_address = TextAreaField('Parent/Guardian Address', validators=[Optional()])
    area_code = StringField('Area Code', validators=[DataRequired(), Length(min=1, max=10, message="Area Code is required and should be max 10 characters")])
    submit = SubmitField('Submit')

class SendAllMessagesForm(FlaskForm):
    message = TextAreaField('Message to All Members', validators=[DataRequired(), Length(min=10, max=1600)],
                            render_kw={"placeholder": "Enter your message here. The system will automatically add the member's Verification Code and Name as a header, and 'From: Kenyasi N1 Youth association' as a footer."})
    submit = SubmitField('Send Message to All')

class CommunityMemberView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        flash('You need to log in to access the admin panel.', 'warning')
        return redirect(url_for('login', next=request.url))

    can_create = True
    can_edit = True
    can_delete = True

    column_list = [
        'first_name', 'last_name', 'gender', 'contact_number', 'area_code',
        'employment_status', 'verification_code', 'created_at'
    ]
    column_searchable_list = ['first_name', 'last_name', 'email', 'verification_code', 'area_code', 'contact_number']
    column_filters = ['gender', 'employment_status', 'area_code', 'created_at']
    column_sortable_list = ['first_name', 'last_name', 'created_at']

    form = CommunityMemberForm

    list_template = 'admin/community_member_list.html'

    def create_model(self, form):
        try:
            model = self.model()
            form.populate_obj(model)
            model.verification_code = generate_verification_code(model.area_code)
            self.session.add(model)
            self._on_model_change(form, model, True)
            self.session.commit()
            flash('Community member created successfully!', 'success')
            return True
        except Exception as ex:
            self.session.rollback()
            flash(f'Failed to create record: {str(ex)}', 'error')
            app.logger.error(f"Error creating community member: {ex}")
            return False

    def update_model(self, form, model):
        try:
            old_area_code = model.area_code
            form.populate_obj(model)
            if old_area_code != model.area_code:
                model.verification_code = generate_verification_code(model.area_code)
            self._on_model_change(form, model, False)
            self.session.commit()
            flash('Community member updated successfully!', 'success')
            return True
        except Exception as ex:
            self.session.rollback()
            flash(f'Failed to update record: {str(ex)}', 'error')
            app.logger.error(f"Error updating community member: {ex}")
            return False

    @expose('/send-sms/<int:member_id>', methods=['GET', 'POST'])
    @login_required
    def send_sms_view(self, member_id):
        member = db.session.get(CommunityMember, member_id)
        if not member:
            flash('Community member not found.', 'danger')
            return redirect(url_for('communitymember.index_view'))

        if request.method == 'POST':
            message = request.form.get('message')
            if not message:
                flash('SMS message cannot be empty.', 'danger')
                return self.render('admin/send_sms_form.html', member=member, message_text="") 

            if member.contact_number:
                if send_sms(member.contact_number, message, 
                            verification_code=member.verification_code, 
                            first_name=member.first_name, 
                            last_name=member.last_name):
                    flash(f'SMS sent to {member.first_name} {member.last_name} ({member.contact_number})', 'success')
                else:
                    flash(f'Failed to send SMS to {member.first_name} {member.last_name}. Check logs for details.', 'danger')
            else:
                flash(f'No contact number for {member.first_name} {member.last_name}. SMS not sent.', 'warning')
            
            return redirect(url_for('communitymember.index_view')) 

        return self.render('admin/send_sms_form.html', member=member, message_text="")

    @expose('/send-all-sms/', methods=['GET', 'POST'])
    @login_required
    def send_all_sms_view(self):
        form = SendAllMessagesForm()
        if form.validate_on_submit():
            message = form.message.data
            all_members = db.session.query(CommunityMember).all()
            
            sent_count = 0
            failed_count = 0
            no_contact_count = 0

            for member in all_members:
                if member.contact_number:
                    if send_sms(member.contact_number, message, 
                                verification_code=member.verification_code, 
                                first_name=member.first_name, 
                                last_name=member.last_name):
                        sent_count += 1
                    else:
                        failed_count += 1
                else:
                    no_contact_count += 1
            
            flash(f'Bulk SMS operation completed: {sent_count} sent, {failed_count} failed, {no_contact_count} members had no contact number.', 'info')
            return redirect(url_for('admin.index')) 

        return self.render('admin/send_all_sms_form.html', form=form)


# --- Flask-Admin Initialization ---
admin = Admin(app, name='Community Members Admin', template_mode='bootstrap3',
              index_view=MyAdminIndexView(url='/admin'))

admin.add_view(CommunityMemberView(CommunityMember, db.session, name='Community Members'))

# --- Login Form ---
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Login')

# --- Routes ---
@app.route('/')
def index():
    return redirect(url_for('login'))

# ... (your existing app.py code) ...

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('admin.index'))

    form = LoginForm()
    if form.validate_on_submit():
        username_attempt = form.username.data
        password_attempt = form.password.data

        # --- ADD THESE DEBUG PRINT STATEMENTS HERE ---
        print(f"\n--- Login Attempt DEBUG ---")
        print(f"Attempting login for username: '{username_attempt}'")
        print(f"Password attempt: '{password_attempt}'") # Be careful not to log passwords in production!
        # --- END DEBUG STATEMENTS ---

        user = db.session.query(User).filter_by(username=username_attempt).first()

        # --- ADD THESE DEBUG PRINT STATEMENTS HERE ---
        print(f"User found in DB: {'Yes' if user else 'No'}")
        if user:
            print(f"Stored username: '{user.username}'")
            print(f"Stored password_hash: '{user.password_hash}'")
            password_check_result = user.check_password(password_attempt)
            print(f"check_password_hash result: {password_check_result}")
        else:
            print(f"User not found in database.")
        print(f"---------------------------\n")
        # --- END DEBUG STATEMENTS ---

        if user is None or not user.check_password(password_attempt):
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        flash('Logged in successfully!', 'success')
        next_page = request.args.get('next')
        return redirect(next_page or url_for('admin.index'))
    return render_template('login.html', form=form)

# ... (rest of your app.py code) ...
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/print_member/<int:member_id>')
@login_required
def print_member_info(member_id):
    member = db.session.get(CommunityMember, member_id)
    if not member:
        flash('Community member not found.', 'danger')
        return redirect(url_for('communitymember.index_view'))
    
    return render_template('admin/print_member.html', member=member, print_on_load=True)


# --- Flask CLI Commands for Database Management (UPDATED CREDENTIALS) ---
@app.cli.command("init-db")
def init_db_command():
    """Clear existing data and create new tables, then add/update admin user."""
    print("Attempting to initialize database...")
    with app.app_context():
        # Optional: uncomment db.drop_all() if you want to completely reset the database
        # db.drop_all()
        db.create_all()

        # Define the NEW admin credentials
        new_admin_username = 'user'        # NEW Username
        new_admin_password = 'executive@2025' # NEW Password

        admin_user = db.session.query(User).filter_by(username=new_admin_username).first()
        if not admin_user:
            admin_user = User(username=new_admin_username)
            admin_user.set_password(new_admin_password)
            db.session.add(admin_user)
            db.session.commit()
            print(f"Database initialized: Tables created and admin user '{new_admin_username}' (password '{new_admin_password}') created.")
        else:
            # If admin user exists, update its password if it's different
            if not admin_user.check_password(new_admin_password):
                admin_user.set_password(new_admin_password)
                db.session.commit()
                print(f"Admin user '{new_admin_username}' already exists. Password reset to '{new_admin_password}'.")
            else:
                print(f"Database tables created. Admin user '{new_admin_username}' already exists (not created again).")

        # Optional: Remove old 'admin', 'k1youthassociation', 'executive' users if they exist
        old_usernames = ['admin', 'k1youthassociation', 'executive'] # Include 'executive'
        for old_user_name in old_usernames:
            if old_user_name != new_admin_username: # Only delete if it's not the new active user
                old_user = db.session.query(User).filter_by(username=old_user_name).first()
                if old_user:
                    db.session.delete(old_user)
                    db.session.commit()
                    print(f"Old '{old_user_name}' user removed from database.")


    print("Database initialization complete.")

# app.py

# ... (your existing code) ...

# Add this temporary route for debugging
# @app.route('/test_password_hash')
# def test_password_hash():
#     test_password = 'executive@2025'
    
#     # Generate the hash for the test password
#     generated_hash = generate_password_hash(test_password)
    
#     # Get the user from the database
#     user = db.session.query(User).filter_by(username='user').first()

#     output = []
#     output.append(f"<h2>Password Hashing Test</h2>")
#     output.append(f"<p>Test Password: <b>{test_password}</b></p>")
#     output.append(f"<p>Generated Hash for test_password: <code>{generated_hash}</code></p>")

#     if user:
#         output.append(f"<p>User 'user' found in database.</p>")
#         output.append(f"<p>Stored password_hash for 'user': <code>{user.password_hash}</code></p>")
        
#         # Compare the test password with the stored hash
#         check_with_stored = check_password_hash(test_password, user.password_hash)
#         output.append(f"<p>Check `test_password` ('{test_password}') against `stored_hash`: <b>{check_with_stored}</b></p>")
        
#         # Compare the test password with the newly generated hash
#         check_with_generated = check_password_hash(test_password, generated_hash)
#         output.append(f"<p>Check `test_password` ('{test_password}') against `generated_hash`: <b>{check_with_generated}</b></p>")
        
#         # Add a specific check for the exact hash values
#         if user.password_hash == generated_hash:
#             output.append("<p><b>CRITICAL: Stored hash EXACTLY MATCHES newly generated hash!</b> (This might mean the hash is simple or the user was just reset)</p>")
#         else:
#             output.append("<p><b>CRITICAL: Stored hash DOES NOT EXACTLY MATCH newly generated hash!</b> (This is normal after set_password, as salts are random)</p>")

#     else:
#         output.append(f"<p>User 'user' NOT found in database. Please run `flask init-db`.</p>")

#     return Response("".join(output))

# ... (rest of your app.py, including your @app.cli.command("init-db") and if __name__ == '__main__': blocks) ...


# if __name__ == '__main__':
#     # This block is for development use (python app.py) and is NOT run by Gunicorn.
#     # It ensures tables exist and the specific admin user is created/updated for local dev.
#     with app.app_context():
#         db.create_all() # Ensure tables exist for dev

#         # Define the NEW admin credentials for local run
#         new_admin_username = 'executive'        # NEW Username
#         new_admin_password = 'KSYA2025' # NEW Password

#         admin_user = db.session.query(User).filter_by(username=new_admin_username).first()
#         if not admin_user:
#             admin_user = User(username=new_admin_username)
#             admin_user.set_password(new_admin_password)
#             db.session.add(admin_user)
#             db.session.commit()
#             app.logger.info(f"Initial admin user '{new_admin_username}' created with password '{new_admin_password}'")
#             print(f"Initial admin user '{new_admin_username}' created with password '{new_admin_password}'")
#         else:
#             # Ensure password is correct for local dev convenience
#             if not admin_user.check_password(new_admin_password):
#                 admin_user.set_password(new_admin_password)
#                 db.session.commit()
#                 app.logger.info(f"Admin user '{new_admin_username}' already exists. Password reset to '{new_admin_password}' for local dev.")
#                 print(f"Admin user '{new_admin_username}' already exists. Password reset to '{new_admin_password}' for local dev.")

#         # Optional: Remove old 'admin', 'k1youthassociation', 'executive' users if they exist
#         old_usernames = ['admin', 'k1youthassociation', 'executive'] # Include 'executive'
#         for old_user_name in old_usernames:
#             if old_user_name != new_admin_username: # Only delete if it's not the new active user
#                 old_user = db.session.query(User).filter_by(username=old_user_name).first()
#                 if old_user:
#                     db.session.delete(old_user)
#                     db.session.commit()
#                     app.logger.info(f"Old '{old_user_name}' user removed for local dev.")
if __name__ == '__main__':
    # --- TEMPORARY TEST CODE ONLY ---
    print("\n--- Running direct password test in __main__ block ---")

    with app.app_context():
        db.create_all() # Ensure tables exist

        test_username = 'tester'
        test_password = 'test' # Super simple password

        # Clean up old test user if it exists
        tester_user = db.session.query(User).filter_by(username=test_username).first()
        if tester_user:
            db.session.delete(tester_user)
            db.session.commit()
            print(f"Old user '{test_username}' removed.")

        # Create a new user with the super simple password
        tester_user = User(username=test_username)
        tester_user.set_password(test_password)
        db.session.add(tester_user)
        db.session.commit()
        print(f"User '{test_username}' created with password '{test_password}'.")

        # Retrieve the user fresh from the DB
        retrieved_user = db.session.query(User).filter_by(username=test_username).first()
        if retrieved_user:
            print(f"Retrieved user: {retrieved_user.username}")
            print(f"Stored hash: {retrieved_user.password_hash}")

            # Directly test check_password on the retrieved user
            is_password_correct = retrieved_user.check_password(test_password)
            print(f"Calling retrieved_user.check_password('{test_password}'): {is_password_correct}")
        else:
            print(f"ERROR: Could not retrieve user '{test_username}' after creation.")

        print("--- End direct password test ---")

    app.run(debug=True)
