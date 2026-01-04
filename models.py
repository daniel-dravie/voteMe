from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Class(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    year = db.Column(db.Integer)
    students = db.relationship('User', back_populates='classroom', lazy=True)
    candidates = db.relationship('Candidate', back_populates='classroom', lazy=True)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    index_number = db.Column(db.String(20), unique=True)
    name = db.Column(db.String(100))
    password = db.Column(db.String(100))
    role = db.Column(db.String(20))  # admin / voter
    voted = db.Column(db.Boolean, default=False)
    sex = db.Column(db.String(10))
    class_id = db.Column(db.Integer, db.ForeignKey('class.id'))
    classroom = db.relationship('Class', back_populates='students')
    is_deleted = db.Column(db.Boolean, default=False)  # soft-delete flag


class Portfolio(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    candidates = db.relationship('Candidate', back_populates='portfolio', lazy=True)


class Candidate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True)  # Candidate must be a voter
    portfolio_id = db.Column(db.Integer, db.ForeignKey('portfolio.id'))
    class_id = db.Column(db.Integer, db.ForeignKey('class.id'))
    # optional filename of candidate photo stored under static/uploads/candidates/
    photo = db.Column(db.String(255))

    user = db.relationship('User')  # access candidate details from user
    portfolio = db.relationship('Portfolio', back_populates='candidates')
    classroom = db.relationship('Class', back_populates='candidates')
    is_deleted = db.Column(db.Boolean, default=False)  # soft-delete flag


class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    voter_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    candidate_id = db.Column(db.Integer, db.ForeignKey('candidate.id'))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class Election(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    start_time = db.Column(db.DateTime)
    end_time = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=False)
    device_password = db.Column(db.String(100))
    # When True, the public kiosk is open and voters can log in with only their index number
    device_open = db.Column(db.Boolean, default=False)
