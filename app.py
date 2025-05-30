# app.py

import os
import random
import string
import requests
from datetime import datetime, date # Ensure datetime is imported
from dateutil.relativedelta import relativedelta # For age calculation
import urllib.parse # Import for URL parsing and unquoting
import re # NEW: Import for regular expressions

from flask import Flask, redirect, url_for, flash, request, render_template, Response, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin, AdminIndexView, expose
from flask_admin.contrib.sqla import ModelView # Ensure ModelView is correctly imported
from flask_admin.contrib.sqla.filters import FilterLike, DateBetweenFilter
from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, TextAreaField, IntegerField, BooleanField, SubmitField, PasswordField, DateField
from wtforms.validators import DataRequired, Length, Optional, Regexp, Email, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from sqlalchemy import func
from markupsafe import Markup # Import Markup for rendering HTML in column_formatters

# For Excel export
import pandas as pd
from io import BytesIO

# For loading environment variables (like DATABASE_URL) from .env file
from dotenv import load_dotenv
load_dotenv()

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
    # Increased length for scrypt hashes (from 128 to 256)
    password_hash = db.Column(db.String(256), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        # The password parameter comes first in check_password_hash
        return check_password_hash(self.password_hash, password)

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
    # NEW: ID Card Field
    id_card_number = db.Column(db.String(50), unique=True, nullable=False) # Made compulsory

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

# --- SMS Sending Function ---
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

# --- Custom Age Validator ---
def validate_age_range(form, field):
    today = date.today()
    if field.data:
        age = relativedelta(today, field.data).years
        if not (18 <= age <= 45):
            raise ValidationError('Member must be between 18 and 45 years old.')

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
        # NEW: Summary of Professions
        profession_stats = db.session.query(
            CommunityMember.occupation, func.count(CommunityMember.id)
        ).group_by(CommunityMember.occupation).order_by(func.count(CommunityMember.id).desc()).all()
        profession_dict = {
            prof if prof and prof.strip() else 'Not Specified': count
            for prof, count in profession_stats
        }


        stats = {
            'total_members': total_members,
            'employment_status': employment_status_dict,
            'gender': gender_dict,
            'area_code': area_code_dict,
            'professions': profession_dict # Add to stats
        }
        return self.render('admin/index.html', stats=stats)

class CommunityMemberForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired(), Length(max=100)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(max=100)])
    # NEW: Add age range validator
    date_of_birth = DateField('Date of Birth (YYYY-MM-DD)', format='%Y-%m-%d', validators=[DataRequired(), validate_age_range])
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
    # NEW: ID Card Field - compulsory
    id_card_number = StringField('ID Card Number', validators=[DataRequired(), Length(max=50)])
    submit = SubmitField('Submit')

class SendAllMessagesForm(FlaskForm):
    message = TextAreaField('Message to All Members', validators=[DataRequired(), Length(min=10, max=1600)],
                            render_kw={"placeholder": "Enter your message here. The system will automatically add the member's Verification Code and Name as a header, and 'From: Kenyasi N1 Youth association' as a footer."})
    submit = SubmitField('Send Message to All')

# Define a simple Pagination class that mimics the essential attributes expected by model_list.html
# This is a fallback if Flask-Admin's default pagination context isn't fully passed.
class CustomPagination:
    def __init__(self, items, page, per_page, total, sort_field=None, sort_desc=None, search_query=None, filter_args=None):
        self.items = items
        self.page = page
        self.per_page = per_page
        self.total = total
        self.sort_field = sort_field
        self.sort_desc = sort_desc
        self.search_query = search_query
        self.filter_args = filter_args if filter_args is not None else []

        # Calculate total pages, has_prev, has_next etc.
        self.num_pages = (total + per_page - 1) // per_page if per_page > 0 else 0
        self.has_prev = self.page > 0
        self.has_next = (self.page + 1) * self.per_page < self.total
        self.offset = self.page * self.per_page
        self.count = len(items) # Number of items on current page

    def iter_pages(self, left_edge=2, right_edge=2, left_current=2, right_current=3):
        # This implementation is copied from Flask-Admin's Pagination for compatibility
        last_page = self.num_pages - 1
        for num in range(0, self.num_pages):
            if num < left_edge or \
               (num > self.page - left_current - 1 and \
                num < self.page + right_current) or \
               num > last_page - right_edge:
                yield num
            else:
                yield None

class CommunityMemberView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        flash('You need to log in to access the admin panel.', 'warning')
        return redirect(url_for('login', next=request.url))

    can_create = True
    can_edit = True
    can_delete = True
    can_export = True # Explicitly allow export

    # REMOVED '_actions' from column_list to let Flask-Admin handle the actions column automatically
    column_list = [
        'first_name', 'last_name', 'gender', 'contact_number', 'area_code',
        'employment_status', 'verification_code', 'id_card_number', 'created_at'
    ]
    column_searchable_list = ['first_name', 'last_name', 'email', 'verification_code', 'area_code', 'contact_number', 'id_card_number'] # NEW: id_card_number
    # MODIFIED: Define column_filters with Flask-Admin filter objects
    column_filters = [
        FilterLike(CommunityMember.gender, 'Gender'),
        FilterLike(CommunityMember.employment_status, 'Employment Status'),
        FilterLike(CommunityMember.area_code, 'Area Code'),
        DateBetweenFilter(CommunityMember.created_at, 'Registration Date')
    ]
    column_sortable_list = ['first_name', 'last_name', 'created_at']

    form = CommunityMemberForm

    list_template = 'admin/community_member_list.html'

    # NEW: Define column_formatters to add custom buttons
    # These will now be injected into the default actions column created by Flask-Admin
    column_formatters = {
        '_actions': lambda v, c, model, name: Markup(f'''
            <a href="{url_for('communitymember.send_sms_view', member_id=model.id)}" class="btn btn-xs btn-warning" title="Send SMS">
                <span class="glyphicon glyphicon-comment"></span> SMS
            </a>
            <a href="{url_for('print_member_info', member_id=model.id)}" class="btn btn-xs btn-info" title="Print Info" target="_blank">
                <span class="glyphicon glyphicon-print"></span> Print
            </a>
        ''')
    }

    # Override get_save_return_url to sanitize the URL
    def get_save_return_url(self, model, is_created):
        # Get the 'url' parameter from request.args
        return_url_param = request.args.get('url')
        
        if return_url_param:
            # Unquote it first to handle URL-encoded characters like %0A, %20
            decoded_url = urllib.parse.unquote(return_url_param)
            
            # Use regex to remove all whitespace (spaces, tabs, newlines)
            # and then strip any remaining leading/trailing whitespace
            cleaned_url = re.sub(r'\s+', '', decoded_url).strip()

            # Ensure it's an absolute path if it's not empty
            if cleaned_url and not cleaned_url.startswith('/'):
                cleaned_url = '/' + cleaned_url
            
            final_redirect_url = cleaned_url if cleaned_url else url_for('.index_view')
        else:
            final_redirect_url = url_for('.index_view') # Default fallback

        # Log the final URL before returning
        app.logger.warning(f"Final redirect URL after sanitization: '{final_redirect_url}'")
        return final_redirect_url


    # Re-implement index_view to manually handle pagination and context
    @expose('/')
    @login_required
    def index_view(self, **kwargs):
        # Retrieve pagination, sorting, and filtering parameters from the request
        page = request.args.get('page', type=int, default=0)
        per_page = self.page_size # Use the configured page_size
        sort_field = request.args.get('sort', type=str)
        sort_desc = request.args.get('sort_desc', type=int)
        search_query = request.args.get('search', type=str)

        # Start with the base query for the model
        query = self.get_query()

        # Apply search filter if a search query is present
        if search_query and self.column_searchable_list:
            search_filter = self._search_query(search_query)
            if search_filter is not None:
                query = query.filter(search_filter)

        # Manually apply column filters based on request arguments
        active_filters = []
        for flt_obj in self.column_filters:
            for arg_key, arg_value in request.args.items():
                if arg_key.startswith('flt'):
                    try:
                        parts = arg_key.split('__')
                        if len(parts) == 2:
                            filter_column_key = parts[0].split('_', 1)[1]
                            filter_operation = parts[1]

                            if filter_column_key == flt_obj.column.key and filter_operation == flt_obj.operation:
                                # Sanitize arg_value: remove any newline characters
                                sanitized_arg_value = arg_value.replace('\n', '').replace('\r', '')
                                query = flt_obj.apply(query, sanitized_arg_value)
                                active_filters.append({
                                    'column': flt_obj.column.key,
                                    'operation': flt_obj.operation,
                                    'value': sanitized_arg_value, # Use sanitized value here
                                    'name': flt_obj.name
                                })
                                break
                    except Exception as e:
                        app.logger.warning(f"Could not apply filter from {arg_key}={arg_value}: {e}")
                        continue

        # Apply sorting
        if sort_field:
            query = self._apply_sort(query, sort_field, sort_desc)

        # Get total count before pagination
        total_count = query.count()
        print(f"DEBUG: Total members in database: {total_count}") # DEBUG PRINT

        # Fetch data for the current page
        items = query.limit(per_page).offset(page * per_page).all()
        print(f"DEBUG: Number of items fetched for current page: {len(items)}") # DEBUG PRINT

        # Create the custom Pagination object
        model_list = CustomPagination(
            items,
            page,
            per_page,
            total_count,
            sort_field=sort_field,
            sort_desc=sort_desc,
            search_query=search_query,
            filter_args=active_filters
        )

        # Prepare the context dictionary for the template
        template_context = {
            'model_list': model_list,
            'list_columns': self._list_columns, # CORRECTED: Use self._list_columns for (c, name) pairs
            'column_filters': self.column_filters,
            'filters': active_filters,
            'admin_view': self,
            'can_create': self.can_create,
            'can_edit': self.can_edit,
            'can_delete': self.can_delete,
            'can_view_details': self.can_view_details,
            'search_supported': True if self.column_searchable_list else False,
            'column_export_allowed': self.can_export,
            'column_export_list': self.column_list if self.can_export else None,
            'column_display_all_relations': True,
            'column_list_all': True,
            'actions': self.get_actions_list(),
            'page_size': self.page_size,
            'endpoint': self.endpoint,
            'name': self.name,
            'edit_modal': self.edit_modal,
            'create_modal': self.create_modal,
            'can_export': self.can_export,
            'column_display_actions': self.can_edit or self.can_delete or self.can_view_details,
            **kwargs
        }

        # Render the custom list template with the prepared context
        return self.render(self.list_template, **template_context)


    def create_model(self, form):
        try:
            model = self.model()
            form.populate_obj(model)
            model.verification_code = generate_verification_code(model.area_code)
            self.session.add(model)
            self._on_model_change(form, model, True)
            self.session.commit()
            flash('Community member created successfully!', 'success')

            # NEW: Automatic SMS on save
            if model.contact_number:
                welcome_message = "You are registered."
                if send_sms(model.contact_number, welcome_message,
                            verification_code=model.verification_code,
                            first_name=model.first_name,
                            last_name=model.last_name):
                    flash(f'Welcome SMS sent to {model.first_name} {model.last_name}!', 'info')
                else:
                    flash(f'Failed to send welcome SMS to {model.first_name} {model.last_name}.', 'warning')
            else:
                flash(f'No contact number for {model.first_name} {model.last_name}. Welcome SMS not sent.', 'warning')

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

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('admin.index'))

    form = LoginForm()
    if form.validate_on_submit():
        username_attempt = form.username.data
        password_attempt = form.password.data

        # --- DEBUG PRINT STATEMENTS ---
        print(f"\n--- Login Attempt DEBUG ---")
        print(f"Attempting login for username: '{username_attempt}'")
        print(f"Password attempt: '{password_attempt}'")
        # --- END DEBUG STATEMENTS ---

        user = db.session.query(User).filter_by(username=username_attempt).first()

        # --- DEBUG PRINT STATEMENTS ---
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

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# NEW: Excel Export Route
@app.route('/export_members_excel')
@login_required
def export_members_excel():
    members = db.session.query(CommunityMember).all()
    
    # Prepare data for DataFrame
    data = []
    for member in members:
        data.append({
            'Name': f"{member.first_name} {member.last_name}",
            'Verification Code': member.verification_code,
            'Area Code': member.area_code,
            'ID Card Number': member.id_card_number
        })
    
    df = pd.DataFrame(data)
    
    # Create an in-memory BytesIO object to save the Excel file
    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Community Members')
    output.seek(0) # Go to the beginning of the stream

    # Send the file as a response
    return send_file(output,
                     mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                     download_name=f'community_members_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx',
                     as_attachment=True)


@app.route('/print_member/<int:member_id>')
@login_required
def print_member_info(member_id):
    member = db.session.get(CommunityMember, member_id)
    if not member:
        flash('Community member not found.', 'danger')
        return redirect(url_for('communitymember.index_view'))

    # Pass the datetime object to the template
    return render_template('admin/print_member.html', member=member, print_on_load=True, datetime=datetime)


# --- Flask CLI Commands for Database Management ---
@app.cli.command("init-db")
def init_db_command():
    """Clear existing data and create new tables, then add/update admin user."""
    print("Attempting to initialize database...")
    with app.app_context():
        # IMPORTANT: For PostgreSQL, db.drop_all() should be used with extreme caution.
        # It will wipe all data. For initial setup or development, uncommenting this is fine.
        db.drop_all() # UNCOMMENT THIS LINE TEMPORARILY
        db.create_all()

        # Define the NEW admin credentials
        new_admin_username = 'user'
        new_admin_password = 'executive@2025'

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

        # Optional: Remove old users if they exist and are not the new active user
        old_usernames_to_clean = ['admin', 'k1youthassociation', 'executive']
        for old_user_name in old_usernames_to_clean:
            if old_user_name != new_admin_username:
                old_user = db.session.query(User).filter_by(username=old_user_name).first()
                if old_user:
                    db.session.delete(old_user)
                    db.session.commit()
                    print(f"Old '{old_user_name}' user removed from database.")


    print("Database initialization complete.")


if __name__ == '__main__':
    # This block is for development use (python app.py) and is NOT run by Gunicorn.
    # It ensures tables exist and the specific admin user is created/updated for local dev.
    with app.app_context():
        db.create_all() # Ensure tables exist for dev

        # Define the new admin credentials for local run
        new_admin_username = 'user'
        new_admin_password = 'executive@2025'

        admin_user = db.session.query(User).filter_by(username=new_admin_username).first()
        if not admin_user:
            admin_user = User(username=new_admin_username)
            admin_user.set_password(new_admin_password)
            db.session.add(admin_user)
            db.session.commit()
            app.logger.info(f"Initial admin user '{new_admin_username}' created with password '{new_admin_password}'")
            print(f"Initial admin user '{new_admin_username}' created with password '{new_admin_password}'")
        else:
            # Ensure password is correct for local dev convenience
            if not admin_user.check_password(new_admin_password):
                admin_user.set_password(new_admin_password)
                db.session.commit()
                app.logger.info(f"Admin user '{new_admin_username}' already exists. Password reset to '{new_admin_password}' for local dev.")
                print(f"Admin user '{new_admin_username}' already exists. Password reset to '{new_admin_password}' for local dev.")

        # Optional: Remove old users if they exist and are not the new active user
        old_usernames_to_clean = ['admin', 'k1youthassociation', 'executive']
        for old_user_name in old_usernames_to_clean:
            if old_user_name != new_admin_username:
                old_user = db.session.query(User).filter_by(username=old_user_name).first()
                if old_user:
                    db.session.delete(old_user)
                    db.session.commit()
                    app.logger.info(f"Old '{old_user_name}' user removed for local dev.")


    app.run(debug=True)
