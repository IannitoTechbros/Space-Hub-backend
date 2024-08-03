from config import *
from sqlalchemy.orm import validates
from sqlalchemy.ext.associationproxy import association_proxy
from sqlalchemy_serializer import SerializerMixin
from datetime import datetime

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'
    
    serialize_rules = ('-registrations.user',)
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(25), default='users')
    
    @validates('email')
    def validate_email(self, key, address):
        if '@' not in address:
            raise ValueError('Failed email validation')
        return address
    
    def __repr__(self):
        return f'<User {self.name}>'
    
class Space(db.Model):
    __tablename__ = 'spaces'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    capacity = db.Column(db.Integer, nullable=False)
    amenities = db.Column(db.String(255), nullable=False)
    ratecard = db.Column(db.Integer, nullable=False)
    image = db.Column(db.String(255), nullable=True)
    booked = db.Column(db.Boolean, default=False)
    
    def __repr__(self):
        return f'<Space {self.name}>'

class Booking(db.Model):
    __tablename__ = 'bookings'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    space_id = db.Column(db.Integer, db.ForeignKey('spaces.id'), nullable=False)
    hours = db.Column(db.Integer, nullable=False)
    total_amount = db.Column(db.Float, nullable=False)
    booking_date = db.Column(db.DateTime, default=datetime.utcnow)
    payment_status = db.Column(db.String(20), default='pending')
    mpesa_receipt_number = db.Column(db.String(50), nullable=True)
    
    user = db.relationship('User', backref=db.backref('bookings', lazy=True))
    space = db.relationship('Space', backref=db.backref('bookings', lazy=True))
    
    def __repr__(self):
        return f'<Booking {self.id}>'