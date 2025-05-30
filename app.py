import os
import re
from datetime import datetime, date
from dateutil.relativedelta import relativedelta # For age calculation
import urllib.parse # Import for URL parsing and unquoting
import string, random # Import for generate_verification_code

from flask import Flask, redirect, url_for, request, render_template, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_admin import Admin, AdminIndexView, expose # Added expose
from flask_admin.contrib.sqla import ModelView
from flask_admin.form import form
from flask_admin.model.fields import InlineFormField
from sqlalchemy.event import listens_for
from sqlalchemy import create_engine, Column, Integer, String, Text, Boolean, Date, Enum, ForeignKey
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.exc import IntegrityError
from flask_admin.form.widgets import DatePickerWidget # Corrected import path for DatePickerWidget
from wtforms.fields import DateField, TextAreaField
from wtforms import StringField, SubmitField, SelectField, PasswordField, BooleanField # Added SelectField, PasswordField, BooleanField
from wtforms.validators import DataRequired, Length, Optional, Regexp, Email, ValidationError
from flask_admin.babel import gettext
from markupsafe import Markup # Corrected import path for Markup
from flask_admin.actions import action
import pandas as pd
from io import BytesIO
from sqlalchemy.sql import func
from collections import defaultdict
from werkzeug.security import generate_password_hash, check_password_hash # Added for password hashing
from flask_wtf import FlaskForm # ADDED: Import FlaskForm


# For loading environment variables (like DATABASE_URL) from .env file
from dotenv import load_dotenv
load_dotenv() # Load environment variables from .env file

# Configuration
basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
# Use Config class from config.py for configuration
app.config.from_object('config.Config')

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False) # Store hashed passwords!

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return self.username

class CommunityMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False) # Changed from full_name
    last_name = db.Column(db.String(100), nullable=False) # Added last_name
    phone_number = db.Column(db.String(20), unique=True, nullable=False)
    gender = db.Column(db.Enum('Male', 'Female', name='gender_types'), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    employment_status = db.Column(db.Enum('Employed', 'Unemployed', 'Student', 'Retired', name='employment_status_types'), nullable=True)
    profession = db.Column(db.String(120), nullable=True)
    date_of_birth = db.Column(db.Date, nullable=True)
    residence = db.Column(db.String(120), nullable=True)
    area_code = db.Column(db.String(10), nullable=True)
    is_verified = db.Column(db.Boolean, default=False)
    registration_date = db.Column(db.DateTime, default=datetime.utcnow)
    verification_code = db.Column(db.String(20), unique=True, nullable=True) # Added verification_code
    id_card_number = db.Column(db.String(50), unique=True, nullable=True) # TEMPORARILY nullable=True for debugging

    def __repr__(self):
        return f"{self.first_name} {self.last_name}" # Updated __repr__


# Flask-Login User Loader
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Define a simple form for sending bulk SMS
class BulkSMSForm(form.BaseForm):
    message = TextAreaField('Message', validators=[DataRequired()])
    submit = SubmitField('Send SMS to All Members')

# Custom Age Validator
def validate_age_range(form, field):
    today = date.today()
    if field.data:
        age = relativedelta(today, field.data).years
        if not (18 <= age <= 45):
            raise ValidationError('Member must be between 18 and 45 years old.')

# Verification Code Generation
def generate_verification_code(area_code: str) -> str:
    base_string = f"KN1YA{area_code}"
    if len(base_string) >= 10:
        return base_string[:10]
    remaining_length = 10 - len(base_string)
    characters = string.ascii_uppercase + string.digits
    random_suffix = ''.join(random.choice(characters) for _ in range(remaining_length))
    return f"{base_string}{random_suffix}"

# SMS Sending Function (Placeholder - integrate with actual SMS API)
def send_sms(recipient: str, message: str, verification_code: str = "", first_name: str = "", last_name: str = "") -> bool:
    print("DEBUG: Simulating SMS sending...")
    print(f"To: {recipient}")
    print(f"Message: Verification code: {verification_code}\nName: {first_name} {last_name}\n.....................................\n{message}\nFrom: Kenyasi N1 Youth association")
    # In a real application, integrate with an SMS API (e.g., Twilio, Nexmo, Arkesel)
    # This is a placeholder for demonstration purposes.
    return True # Simulate success for now


# Admin Views
class MyAdminIndexView(AdminIndexView):
    @expose('/')
    @login_required
    def index(self):
        # Calculate statistics
        total_members = db.session.query(CommunityMember).count()

        employment_status_raw = db.session.query(CommunityMember.employment_status, func.count(CommunityMember.id)).group_by(CommunityMember.employment_status).all()
        employment_status_dict = {s: c for s, c in employment_status_raw if s is not None}

        gender_raw = db.session.query(CommunityMember.gender, func.count(CommunityMember.id)).group_by(CommunityMember.gender).all()
        gender_dict = {g: c for g, c in gender_raw if g is not None}

        # Extract area code (first 3 digits of phone number if format is consistent)
        area_codes = db.session.query(
            func.substring(CommunityMember.phone_number, 1, 3).label('area_code'),
            func.count(CommunityMember.id)
        ).group_by(func.substring(CommunityMember.phone_number, 1, 3)).order_by(func.count(CommunityMember.id).desc()).limit(5).all()
        area_code_dict = {ac: count for ac, count in area_codes if ac is not None}

        professions_raw = db.session.query(CommunityMember.profession, func.count(CommunityMember.id)).group_by(CommunityMember.profession).all()
        profession_dict = {p: c for p, c in professions_raw if p is not None}


        stats = {
            'total_members': total_members,
            'employment_status': employment_status_dict,
            'gender': gender_dict,
            'area_code': area_code_dict,
            'professions': profession_dict # Include professions in stats
        }
        return self.render('admin/index.html', stats=stats)

# Define the form for CommunityMember
class CommunityMemberForm(FlaskForm): # Changed from form.BaseForm
    first_name = StringField('First Name', validators=[DataRequired(), Length(max=100)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(max=100)])
    # Directly apply DatePickerWidget here
    date_of_birth = DateField('Date of Birth (YYYY-MM-DD)', format='%Y-%m-%d', validators=[DataRequired(), validate_age_range], widget=DatePickerWidget())
    gender = SelectField('Gender', choices=[('Male', 'Male'), ('Female', 'Female'), ('Other', 'Other')], validators=[DataRequired()])
    phone_number = StringField('Phone Number', validators=[DataRequired(), Length(max=20)]) # RENAMED from contact_number, changed to DataRequired()
    email = StringField('Email', validators=[Optional(), Email(), Length(max=120)])
    residence = StringField('Residence', validators=[Optional(), Length(max=120)]) # Changed from address to residence
    employment_status = SelectField('Employment Status', choices=[
        ('Employed', 'Employed'), ('Unemployed', 'Unemployed'),
        ('Student', 'Student'), ('Retired', 'Retired'), ('Other', 'Other')
    ], validators=[Optional()])
    profession = StringField('Occupation', validators=[Optional(), Length(max=100)]) # Changed to Occupation
    employer = StringField('Employer', validators=[Optional(), Length(max=100)])
    parent_guardian_name = StringField('Parent/Guardian Name', validators=[Optional(), Length(max=200)])
    parent_guardian_contact = StringField('Parent/Guardian Contact', validators=[Optional(), Length(max=20)])
    parent_guardian_address = TextAreaField('Parent/Guardian Address', validators=[Optional()])
    area_code = StringField('Area Code', validators=[DataRequired(), Length(min=1, max=10, message="Area Code is required and should be max 10 characters")])
    id_card_number = StringField('ID Card Number', validators=[Optional(), Length(max=50)]) # TEMPORARILY Optional for debugging
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

    # ADDED '_actions' to column_list to ensure it's rendered as a distinct column
    column_list = [
        'first_name', 'last_name', 'phone_number', 'gender', 'email', 'employment_status', 'profession', 'date_of_birth', 'residence', 'area_code', 'is_verified', 'registration_date', 'verification_code', 'id_card_number', '_actions'
    ]
    column_searchable_list = ['first_name', 'last_name', 'phone_number', 'email', 'residence', 'profession', 'area_code', 'verification_code', 'id_card_number']
    column_filters = ['gender', 'employment_status', 'is_verified', 'area_code']
    column_sortable_list = ['first_name', 'last_name', 'registration_date']

    form = CommunityMemberForm # Use the custom form
    form_base_class = FlaskForm # Explicitly set the base form class

    list_template = 'admin/community_member_list.html'

    # Move print_member_info into the ModelView as an exposed endpoint
    @expose('/print_member/<int:member_id>')
    @login_required
    def print_member_info(self, member_id):
        member = db.session.get(CommunityMember, member_id)
        if not member:
            flash('Community member not found.', 'danger')
            return redirect(url_for('.index_view')) # Redirect to current view's index

        # Pass the datetime object to the template
        return render_template('admin/print_member.html', member=member, print_on_load=True, datetime=datetime)


    # NEW: Define a method for formatting the actions column
    def _format_actions_column(self, context, model, name):
        # 'self' here is the CommunityMemberView instance
        # Use self.get_url() to generate URLs within the current blueprint
        print_url = self.get_url('.print_member_info', member_id=model.id)
        return Markup(f'''
            <a href="{self.get_url('.send_sms_view', member_id=model.id)}" class="btn btn-xs btn-warning" title="Send SMS">
                <span class="glyphicon glyphicon-comment"></span> SMS
            </a>
            <a href="{print_url}" class="btn btn-xs btn-info" title="Print Info" target="_blank">
                <span class="glyphicon glyphicon-print"></span> Print
            </a>
        ''')

    # Assign the method to column_formatters
    column_formatters = {
        '_actions': _format_actions_column
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
            flash('DEBUG: Redirecting to index view after successful creation.', 'info') # Added debug flash

            # NEW: Automatic SMS on save
            if model.phone_number:
                welcome_message = "You are registered."
                if send_sms(model.phone_number, welcome_message,
                            verification_code=model.verification_code,
                            first_name=model.first_name,
                            last_name=model.last_name):
                    flash(f'Welcome SMS sent to {model.first_name} {model.last_name}!', 'info')
                else:
                    flash(f'Failed to send welcome SMS to {model.first_name} {model.last_name}.', 'warning')
            else:
                flash(f'No contact number for {model.first_name} {model.last_name}. Welcome SMS not sent.', 'warning')

            # Explicitly redirect to the list view after successful creation
            return redirect(self.get_save_return_url(model, True)) # Use get_save_return_url
        except Exception as ex:
            self.session.rollback()
            flash(f'Failed to create record: {str(ex)}', 'error')
            app.logger.error(f"Error creating community member: {ex}")
            return False # Stay on the form if creation fails

    def update_model(self, form, model):
        try:
            old_area_code = model.area_code
            form.populate_obj(model)
            if old_area_code != model.area_code:
                model.verification_code = generate_verification_code(model.area_code)
            self._on_model_change(form, model, False)
            self.session.commit()
            flash('Community member updated successfully!', 'success')
            flash('DEBUG: Redirecting to index view after update.', 'info') # Added debug flash
            return redirect(self.get_save_return_url(model, False)) # Use get_save_return_url
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

            if member.phone_number:
                if send_sms(member.phone_number, message,
                            verification_code=member.verification_code,
                            first_name=member.first_name,
                            last_name=member.last_name):
                    flash(f'SMS sent to {member.first_name} {member.last_name}!', 'success')
                else:
                    flash(f'Failed to send SMS to {member.first_name} {member.last_name}.', 'danger')
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
                if member.phone_number:
                    if send_sms(member.phone_number, message,
                                verification_code=member.verification_code,
                                first_name=member.first_name,
                                last_name=member.last_name):
                        sent_count += 1
                    else:
                        failed_count += 1
                else:
                    no_contact_count += 1

            flash(f'Bulk SMS operation completed: {sent_count} sent, {failed_count} failed, {no_contact_count} members had no contact number.', 'info')
            return redirect(url_for('communitymember.index_view')) # Redirect to community member list

        return self.render('admin/send_all_sms_form.html', form=form)


# Flask-Admin Setup
admin = Admin(app, name='Community Database', template_mode='bootstrap3', index_view=MyAdminIndexView())

admin.add_view(ModelView(User, db.session, category='Admin'))
admin.add_view(CommunityMemberView(CommunityMember, db.session))


# Login Form
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Login')

# Routes
@app.route('/')
def home():
    if current_user.is_authenticated:
        # Redirect to Flask-Admin dashboard if logged in
        return redirect(url_for('admin.index'))
    return render_template('home.html') # A simple public home page if not logged in

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('admin.index'))

    form = LoginForm()
    if form.validate_on_submit():
        username_attempt = form.username.data
        password_attempt = form.password.data

        user = db.session.query(User).filter_by(username=username_attempt).first()

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

# Export to Excel Route
@app.route('/export_members_excel')
@login_required
def export_members_excel():
    members = db.session.query(CommunityMember).all()
    
    # Prepare data for DataFrame
    data = []
    for member in members:
        data.append({
            'ID': member.id,
            'First Name': member.first_name,
            'Last Name': member.last_name,
            'Phone Number': member.phone_number,
            'Gender': member.gender,
            'Email': member.email,
            'Employment Status': member.employment_status,
            'Profession': member.profession,
            'Date of Birth': member.date_of_birth.strftime('%Y-%m-%d') if member.date_of_birth else 'N/A',
            'Residence': member.residence,
            'Area Code': member.area_code,
            'Is Verified': member.is_verified,
            'Registration Date': member.registration_date.strftime('%Y-%m-%d %H:%M:%S') if member.registration_date else 'N/A',
            'Verification Code': member.verification_code,
            'ID Card Number': member.id_card_number
        })
    df = pd.DataFrame(data)

    # Create Excel file in memory
    output = BytesIO()
    writer = pd.ExcelWriter(output, engine='xlsxwriter') # Using xlsxwriter for broader compatibility
    df.to_excel(writer, index=False, sheet_name='CommunityMembers')
    writer.close()
    output.seek(0)

    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        download_name=f'community_members_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx',
        as_attachment=True
    )

# Database Initialization (for development/first run)
# Moved from @app.before_first_request decorator
def initialize_database():
    with app.app_context():
        # Always drop and create all tables to ensure schema is up-to-date
        # This is for development convenience. In production, use migrations.
        print("Dropping all existing tables...")
        db.drop_all()
        print("Creating all new tables...")
        db.create_all()
        print("Tables created successfully.")

        # Create a default admin user if none exists
        # This query will now run on a fresh, newly created database.
        if not User.query.filter_by(username='user').first():
            admin_user = User(username='user')
            admin_user.set_password('executive@2025')
            db.session.add(admin_user)
            db.session.commit()
            print("Default admin user created: user/executive@2025")
        else:
            # If user exists (e.g., from a previous run where tables weren't dropped),
            # ensure its password is correct.
            admin_user = User.query.filter_by(username='user').first()
            if not admin_user.check_password('executive@2025'):
                admin_user.set_password('executive@2025')
                db.session.commit()
                print("Admin user 'user' already exists. Password reset to 'executive@2025'.")
            else:
                print("Admin user 'user' already exists and password is correct.")

        # Optional: Remove old users if they exist and are not the new active user
        old_usernames_to_clean = ['admin', 'k1youthassociation', 'executive']
        for old_user_name in old_usernames_to_clean:
            if old_user_name != 'user': # Ensure we don't delete the current user
                old_user = db.session.query(User).filter_by(username=old_user_name).first()
                if old_user:
                    db.session.delete(old_user)
                    db.session.commit()
                    print(f"Old '{old_user_name}' user removed from database.")

        print("Database initialization complete.")

# Run the app
if __name__ == '__main__':
    initialize_database() # Call the function directly
    app.run(debug=True)
