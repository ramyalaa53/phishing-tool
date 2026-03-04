from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, Length

class RegisterForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=2, max=120)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=4)])
    confirm = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class URLForm(FlaskForm):
    url = StringField('URL', validators=[DataRequired(), Length(min=5)])
    submit = SubmitField('Check')

class BlacklistForm(FlaskForm):
    pattern = StringField('Pattern', validators=[DataRequired(), Length(min=2)])
    note = StringField('Note')
    submit = SubmitField('Add to Blacklist')

class WhitelistForm(FlaskForm):
    pattern = StringField('Pattern', validators=[DataRequired(), Length(min=2)])
    note = StringField('Note')
    submit = SubmitField('Add to Whitelist')