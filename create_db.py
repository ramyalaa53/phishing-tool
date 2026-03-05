from models import db, User
from werkzeug.security import generate_password_hash
from app import create_app
import os
app = create_app()
app.app_context().push()

db.create_all()

if not User.query.filter_by(email='ramyalaa100@gmail.com').first():
    admin = User(name='Admin', email='ramyalaa100@gmail.com', role='admin',
                 password_hash=generate_password_hash('246810'))
    db.session.add(admin)
    db.session.commit()
    print("Created default admin: admin@example.com / 1234")
else:
    print("Admin already exists.")