import os
import random
import string
import requests
from datetime import datetime, date
from dateutil.relativedelta import relativedelta
import urllib.parse
import re

from flask import Flask, redirect, url_for, flash, request, render_template, Response, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin, AdminIndexView, expose
from flask_admin.actions import action
from flask_admin.contrib.sqla import ModelView
from flask_admin.contrib.sqla.filters import FilterLike, DateBetweenFilter
from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, TextAreaField, IntegerField, BooleanField, SubmitField, PasswordField, DateField
from wtforms.validators import DataRequired, Length, Optional, Regexp, Email, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from sqlalchemy import func
from markupsafe import Markup

# For Excel export
import pandas as pd
from io import BytesIO
import xlsxwriter # Ensure this is installed: pip install XlsxWriter openpyxl

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
    password_hash = db.Column(db.String(256), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
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
    phone_number = db.Column(db.String(20), unique=True, nullable=True) # Changed to nullable=True
    gender = db.Column(db.String(10), nullable=False) # Changed from Enum to String for simplicity
    email = db.Column(db.String(120), unique=True, nullable=True)
    employment_status = db.Column(db.String(50), nullable=True) # Changed from Enum to String for simplicity
    profession = db.Column(db.String(100), nullable=True)
    employer = db.Column(db.String(100), nullable=True)
    parent_guardian_name = db.Column(db.String(200), nullable=True)
    parent_guardian_contact = db.Column(db.String(20), nullable=True)
    parent_guardian_address = db.Column(db.Text, nullable=True)
    area_code = db.Column(db.String(10), nullable=False)
    verification_code = db.Column(db.String(20), unique=True, nullable=True)
    registration_date = db.Column(db.DateTime, default=datetime.utcnow)
    id_card_number = db.Column(db.String(50), unique=True, nullable=False) # Changed to nullable=False
    date_of_birth = db.Column(db.Date, nullable=True) # Re-added date_of_birth
    residence = db.Column(db.String(120), nullable=True) # Re-added residence

    def __repr__(self):
        return f'<CommunityMember {self.first_name} {self.last_name}>'

    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"

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
# This is a placeholder. In a real app, integrate with Arkesel or another SMS API.
def send_sms(recipient: str, message: str, verification_code: str = "", full_name: str = "") -> bool:
    app.logger.info("DEBUG: Entering send_sms function. Using GET request logic.")

    # These would typically come from app.config
    api_key = app.config.get('ARKESEL_API_KEY')
    sender_id = app.config.get('ARKESEL_SENDER_ID')
    url = "https://sms.arkesel.com/sms/api"

    if not api_key or not sender_id:
        app.logger.error("ARKESEL_API_KEY or ARKESEL_SENDER_ID not configured.")
        return False

    if recipient:
        recipient = recipient.strip()
        # Basic formatting for Ghanaian numbers for Arkesel (assuming 02x -> 2332x)
        if recipient.startswith('+'):
            recipient = recipient.lstrip('+')
        if recipient.startswith('0'):
            recipient = '233' + recipient[1:]
        elif not recipient.startswith('233'):
            recipient = '233' + recipient
        recipient = '+' + recipient # Arkesel prefers +countrycode format
    else:
        app.logger.warning("Attempted to send SMS to an empty recipient number.")
        return False

    final_message_parts = []

    if verification_code:
        final_message_parts.append(f"Verification code: {verification_code}")

    if full_name:
        final_message_parts.append(f"Name: {full_name}")

    if (verification_code or full_name) and message.strip():
        final_message_parts.append(".....................................")

    if message.strip():
        final_message_parts.append(message.strip())

    final_message_parts.append("From: Kenyasi N1 Youth association")

    final_message = "\n".join(final_message_parts)

    payload = {
        "action": "send-sms",
        "api_key": api_key,
        "to": recipient,
        "from": sender_id,
        "sms": final_message
    }

    try:
        app.logger.info(f"Attempting to send SMS to {recipient} with message: \n'{final_message}'\n using GET request.")
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
        profession_stats = db.session.query(
            CommunityMember.profession, func.count(CommunityMember.id)
        ).group_by(CommunityMember.profession).order_by(func.count(CommunityMember.id).desc()).all()
        profession_dict = {
            prof if prof and prof.strip() else 'Not Specified': count
            for prof, count in profession_stats
        }

        stats = {
            'total_members': total_members,
            'employment_status': employment_status_dict,
            'gender': gender_dict,
            'area_code': area_code_dict,
            'professions': profession_dict
        }
        return self.render('admin/index.html', stats=stats)

class CommunityMemberForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired(), Length(max=100)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(max=100)])
    date_of_birth = DateField('Date of Birth (YYYY-MM-DD)', format='%Y-%m-%d', validators=[DataRequired(), validate_age_range])
    gender = SelectField('Gender', choices=[('Male', 'Male'), ('Female', 'Female'), ('Other', 'Other')], validators=[DataRequired()])
    phone_number = StringField('Phone Number', validators=[Optional(), Length(max=20)]) # Changed to Optional
    email = StringField('Email', validators=[Optional(), Email(), Length(max=120)])
    residence = TextAreaField('Residence', validators=[Optional()])
    employment_status = SelectField('Employment Status', choices=[
        ('Employed', 'Employed'), ('Unemployed', 'Unemployed'),
        ('Student', 'Student'), ('Retired', 'Retired'), ('Other', 'Other')
    ], validators=[Optional()])
    profession = StringField('Profession', validators=[Optional(), Length(max=100)])
    employer = StringField('Employer', validators=[Optional(), Length(max=100)])
    parent_guardian_name = StringField('Parent/Guardian Name', validators=[Optional(), Length(max=200)])
    parent_guardian_contact = StringField('Parent/Guardian Contact', validators=[Optional(), Length(max=20)])
    parent_guardian_address = TextAreaField('Parent/Guardian Address', validators=[Optional()])
    area_code = StringField('Area Code', validators=[DataRequired(), Length(min=1, max=10, message="Area Code is required and should be max 10 characters")])
    id_card_number = StringField('ID Card Number', validators=[DataRequired(), Length(max=50)]) # Changed to DataRequired
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
    can_export = True

    column_list = [
        'first_name', 'last_name', 'phone_number', 'gender', 'email', 'employment_status', 'profession',
        'date_of_birth', 'residence', 'area_code', 'verification_code', 'id_card_number', 'registration_date', '_actions'
    ]
    column_searchable_list = ['first_name', 'last_name', 'phone_number', 'email', 'verification_code', 'area_code', 'id_card_number', 'residence', 'profession']
    
    column_filters = [
        FilterLike(CommunityMember.first_name, 'First Name'),
        FilterLike(CommunityMember.last_name, 'Last Name'),
        FilterLike(CommunityMember.gender, 'Gender'),
        FilterLike(CommunityMember.employment_status, 'Employment Status'),
        FilterLike(CommunityMember.area_code, 'Area Code'),
        FilterLike(CommunityMember.verification_code, 'Verification Code'),
        FilterLike(CommunityMember.id_card_number, 'ID Card Number'),
        DateBetweenFilter(CommunityMember.registration_date, 'Registration Date')
    ]
    column_sortable_list = ['first_name', 'last_name', 'registration_date', 'date_of_birth']

    form = CommunityMemberForm

    list_template = 'admin/community_member_list.html'

    actions = ['send_sms_action', 'print_info_action'] # Renamed actions to avoid conflict

    # NEW: Define a method for formatting the actions column
    def _actions_formatter(self, context, model, name):
        # 'self' here is the CommunityMemberView instance
        # Use self.get_url() to generate URLs within the current blueprint
        edit_url = self.get_url('.edit_view', id=model.id, url=self.get_save_return_url(model, False))
        delete_url = self.get_url('.delete_view', id=model.id, url=self.get_save_return_url(model, False))
        send_sms_url = self.get_url('.send_sms_view', member_id=model.id)
        # Corrected: Use url_for directly for global route 'print_member_info'
        print_url = url_for('print_member_info', member_id=model.id) 

        return Markup(f'''
            <a href="{edit_url}" class="btn btn-xs btn-primary" title="Edit record">
                <span class="glyphicon glyphicon-pencil"></span>
            </a>
            <form class="icon" method="POST" action="{delete_url}">
                <button onclick="return confirm('Are you sure you want to delete this record?');" class="btn btn-xs btn-danger" title="Delete record">
                    <span class="glyphicon glyphicon-trash"></span>
                </button>
            </form>
            <a href="{send_sms_url}" class="btn btn-xs btn-warning" title="Send SMS">
                <span class="glyphicon glyphicon-comment"></span> SMS
            </a>
            <a href="{print_url}" class="btn btn-xs btn-info" title="Print Info" target="_blank">
                <span class="glyphicon glyphicon-print"></span> Print
            </a>
        ''')

    # Assign the method to column_formatters
    column_formatters = {
        '_actions': _actions_formatter
    }

    def get_save_return_url(self, model, is_created):
        return_url_param = request.args.get('url')
        
        if return_url_param:
            decoded_url = urllib.parse.unquote(return_url_param)
            cleaned_url = re.sub(r'\s+', '', decoded_url).strip()
            if cleaned_url and not cleaned_url.startswith('/'):
                cleaned_url = '/' + cleaned_url
            final_redirect_url = cleaned_url if cleaned_url else url_for('.index_view')
        else:
            final_redirect_url = url_for('.index_view')

        app.logger.warning(f"Final redirect URL after sanitization: '{final_redirect_url}'")
        return final_redirect_url

    @expose('/')
    @login_required
    def index_view(self, **kwargs):
        # Retrieve pagination, sorting, and filtering parameters from the request
        page = request.args.get('page', type=int, default=0)
        per_page = self.page_size # Use the configured page_size
        sort_field = request.args.get('sort', type=str)
        sort_desc = request.args.get('sort_desc', type=bool, default=False) # Changed to bool

        search_query = request.args.get('search', type=str)

        # Start with the base query for the model
        query = self.get_query()

        # Apply search filter if a search query is present
        if search_query and self.column_searchable_list:
            search_filter_clauses = []
            for col_name in self.column_searchable_list:
                col = getattr(self.model, col_name, None)
                if col is not None:
                    search_filter_clauses.append(col.ilike(f'%{search_query}%'))
            if search_filter_clauses:
                query = query.filter(db.or_(*search_filter_clauses))

        # Manually apply column filters based on request arguments
        active_filters = []
        for i in range(5): # Check for up to 5 filters, adjust as needed
            flt_col_key = f'flt{i}_0'
            flt_op_key = f'flt{i}_1'
            flt_val_key = f'flt{i}_2'

            column_name = request.args.get(flt_col_key)
            operation = request.args.get(flt_op_key)
            value = request.args.get(flt_val_key)

            if column_name and operation and value:
                # Find the filter object that matches the column and operation
                for filter_obj in self.column_filters:
                    # FilterLike and DateBetweenFilter use column name directly
                    if isinstance(filter_obj, (FilterLike, DateBetweenFilter)):
                        if filter_obj.column.key == column_name and filter_obj.operation == operation:
                            query = filter_obj.apply(query, value)
                            active_filters.append({
                                'column': column_name,
                                'operation': operation,
                                'value': value,
                                'name': filter_obj.name # Display name of the filter
                            })
                            break
                    # Add handling for other filter types if you use them
                    # For simple equality filters on Enum/String columns, the column name is sufficient
                    elif hasattr(filter_obj, 'column') and filter_obj.column.key == column_name and operation == 'eq': # Assuming 'eq' for simple dropdowns
                        col = getattr(self.model, column_name, None)
                        if col is not None:
                            query = query.filter(col == value)
                            active_filters.append({
                                'column': column_name,
                                'operation': operation,
                                'value': value,
                                'name': filter_obj.name
                            })
                            break

        # Apply sorting
        if sort_field:
            sort_column = getattr(self.model, sort_field, None)
            if sort_column is not None:
                if sort_desc:
                    query = query.order_by(sort_column.desc())
                else:
                    query = query.order_by(sort_column.asc())

        # Get total count before pagination
        total_count = query.count()

        # Fetch data for the current page
        items = query.limit(per_page).offset(page * per_page).all()

        # Create the custom Pagination object
        model_list = CustomPagination(
            items,
            page,
            per_page,
            total_count,
            sort_field=sort_field,
            sort_desc=sort_desc,
            search_query=search_query,
            filter_args=active_filters # Pass active_filters for displaying applied filters
        )

        # Prepare the context dictionary for the template
        template_context = {
            'model_list': model_list,
            'list_columns': self._list_columns,
            'column_filters': self.column_filters, # This is the full list of available filters
            'filters': active_filters, # This is the list of currently applied filters
            'admin_view': self,
            'can_create': self.can_create,
            'can_edit': self.can_edit,
            'can_delete': self.can_delete,
            'can_view_details': self.can_view_details,
            'search_supported': True if self.column_searchable_list else False,
            'can_export': self.can_export,
            'actions': self.get_actions_list(),
            'page_size': self.page_size,
            'endpoint': self.endpoint,
            'name': self.name,
            'edit_modal': self.edit_modal,
            'create_modal': self.create_modal,
            'column_display_actions': True, # Always display the actions column
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

            if model.phone_number:
                welcome_message = "You are registered."
                if send_sms(model.phone_number, welcome_message,
                            verification_code=model.verification_code,
                            full_name=model.full_name): # Use full_name property
                    flash(f'Welcome SMS sent to {model.full_name} ({model.phone_number})', 'info')
                else:
                    flash(f'Failed to send welcome SMS to {model.full_name}. Check logs for details.', 'warning')
            else:
                flash(f'No phone number for {model.full_name}. Welcome SMS not sent.', 'warning')

            return True
        except IntegrityError as ex:
            self.session.rollback()
            if 'phone_number' in str(ex) and 'unique constraint' in str(ex).lower():
                flash('A member with this phone number already exists.', 'error')
            elif 'email' in str(ex) and 'unique constraint' in str(ex).lower():
                flash('A member with this email already exists.', 'error')
            elif 'id_card_number' in str(ex) and 'unique constraint' in str(ex).lower():
                flash('A member with this ID Card Number already exists.', 'error')
            else:
                flash(f'Failed to create record: {str(ex)}', 'error')
            app.logger.error(f"IntegrityError creating community member: {ex}")
            return False
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
        except IntegrityError as ex:
            self.session.rollback()
            if 'phone_number' in str(ex) and 'unique constraint' in str(ex).lower():
                flash('A member with this phone number already exists.', 'error')
            elif 'email' in str(ex) and 'unique constraint' in str(ex).lower():
                flash('A member with this email already exists.', 'error')
            elif 'id_card_number' in str(ex) and 'unique constraint' in str(ex).lower():
                flash('A member with this ID Card Number already exists.', 'error')
            else:
                flash(f'Failed to update record: {str(ex)}', 'error')
            app.logger.error(f"IntegrityError updating community member: {ex}")
            return False
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
                            full_name=member.full_name): # Use full_name property
                    flash(f'SMS sent to {member.full_name} ({member.phone_number})', 'success')
                else:
                    flash(f'Failed to send SMS to {member.full_name}. Check logs for details.', 'danger')
            else:
                flash(f'No phone number for {member.full_name}. SMS not sent.', 'warning')

            return redirect(url_for('communitymember.index_view'))

        return self.render('admin/send_sms_form.html', member=member, message_text="")

    @action('send_sms_action', 'Send SMS to Selected', 'Are you sure you want to send SMS to selected members?')
    def send_sms_action(self, ids):
        if not ids:
            flash('No members selected for SMS.', 'warning')
            return redirect(request.url)

        members = db.session.query(CommunityMember).filter(CommunityMember.id.in_(ids)).all()
        
        sent_count = 0
        failed_count = 0
        
        # A generic message for bulk action, as custom messages per recipient are not feasible here
        generic_message = "A general update from Kenyasi N1 Youth Association."

        for member in members:
            if member.phone_number:
                if send_sms(member.phone_number, generic_message,
                            verification_code=member.verification_code,
                            full_name=member.full_name): # Use full_name property
                    sent_count += 1
                else:
                    failed_count += 1
            else:
                flash(f'No phone number for {member.full_name}. Skipping SMS.', 'warning')

        if sent_count > 0:
            flash(f'Successfully sent SMS to {sent_count} members.', 'success')
        if failed_count > 0:
            flash(f'Failed to send SMS to {failed_count} members. Check logs.', 'danger')
        
        return redirect(request.url)

    @action('print_info_action', 'Print Selected Info', 'Are you sure you want to print information for selected members?')
    def print_info_action(self, ids):
        if not ids:
            flash('No members selected for printing.', 'warning')
            return redirect(request.url)
        
        members = db.session.query(CommunityMember).filter(CommunityMember.id.in_(ids)).all()
        member_names = ", ".join([m.full_name for m in members]) # Use full_name property
        flash(f'Information for {member_names} marked for printing. (Implementation for batch printing needs to be added)', 'info')
        # For batch printing, you would typically generate a single PDF or a printable page with all selected members.
        # This action currently just flashes a message.
        return redirect(request.url)


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
                                full_name=member.full_name): # Use full_name property
                        sent_count += 1
                    else:
                        failed_count += 1
                else:
                    no_contact_count += 1

            flash(f'Bulk SMS operation completed: {sent_count} sent, {failed_count} failed, {no_contact_count} members had no phone number.', 'info')
            return redirect(url_for('admin.index'))

        return self.render('admin/send_all_sms_form.html', form=form)


# Flask-Admin Setup
admin = Admin(app, name='Community Members Admin', template_mode='bootstrap3',
              index_view=MyAdminIndexView(url='/admin'))

admin.add_view(ModelView(User, db.session, name='Admin Users'))
admin.add_view(CommunityMemberView(CommunityMember, db.session, name='Community Members'))


# Login Form
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Login')

# Routes
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

# NEW: Excel Export Route
@app.route('/export_members_excel')
@login_required
def export_members_excel():
    members = db.session.query(CommunityMember).all()
    
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
            'Verification Code': member.verification_code,
            'ID Card Number': member.id_card_number,
            'Registration Date': member.registration_date.strftime('%Y-%m-%d %H:%M:%S') if member.registration_date else 'N/A'
        })
    
    df = pd.DataFrame(data)
    
    output = BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer: # Using xlsxwriter for broader compatibility
        df.to_excel(writer, index=False, sheet_name='Community Members')
    output.seek(0)

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

    return render_template('admin/print_member.html', member=member, print_on_load=True, datetime=datetime)


# --- Flask CLI Commands for Database Management ---
@app.cli.command("init-db")
def init_db_command():
    """Clear existing data and create new tables, then add/update admin user."""
    print("Attempting to initialize database...")
    with app.app_context():
        db.drop_all()
        db.create_all()

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
            if not admin_user.check_password(new_admin_password):
                admin_user.set_password(new_admin_password)
                db.session.commit()
                print(f"Admin user '{new_admin_username}' already exists. Password reset to '{new_admin_password}'.")
            else:
                print(f"Database tables created. Admin user '{new_admin_username}' already exists (not created again).")

        old_usernames_to_clean = ['admin', 'k1youthassociation', 'executive']
        for old_user_name in old_usernames_to_clean:
            if old_user_name != new_admin_username:
                old_user = db.session.query(User).filter_by(username=old_user_name).first()
                if old_user:
                    db.session.delete(old_user)
                    db.session.commit()
                    app.logger.info(f"Old '{old_user_name}' user removed for local dev.")

    print("Database initialization complete.")


if __name__ == '__main__':
    with app.app_context():
        db.drop_all()
        db.create_all()

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
            if not admin_user.check_password(new_admin_password):
                admin_user.set_password(new_admin_password)
                db.session.commit()
                app.logger.info(f"Admin user '{new_admin_username}' already exists. Password reset to '{new_admin_password}' for local dev.")
                print(f"Admin user '{new_admin_username}' already exists. Password reset to '{new_admin_password}' for local dev.")

        old_usernames_to_clean = ['admin', 'k1youthassociation', 'executive']
        for old_user_name in old_usernames_to_clean:
            if old_user_name != new_admin_username:
                old_user = db.session.query(User).filter_by(username=old_user_name).first()
                if old_user:
                    db.session.delete(old_user)
                    db.session.commit()
                    app.logger.info(f"Old '{old_user_name}' user removed for local dev.")

    app.run(debug=True)
