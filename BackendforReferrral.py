from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import re
import uuid
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['JWT_SECRET_KEY'] = 'supersecretkey'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

class User(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=str(uuid.uuid4()))
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    referral_code = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4())[:8])
    referred_by = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Referral(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    referrer_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    referred_user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    date_referred = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending')

@app.errorhandler(500)
def internal_server_error(e):
    return jsonify({"error": "An unexpected error occurred. Please try again later."}), 500

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    username = data.get('username')
    password = data.get('password')
    referral_code = data.get('referral_code')

    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({"error": "Invalid email format"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters long"}), 400
    if User.query.filter_by(email=email).first() or User.query.filter_by(username=username).first():
        return jsonify({"error": "Email or username already exists"}), 400

    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    referred_by = User.query.filter_by(referral_code=referral_code).first() if referral_code else None
    
    new_user = User(email=email, username=username, password_hash=password_hash, referred_by=referred_by.id if referred_by else None)
    db.session.add(new_user)
    db.session.commit()

    if referred_by:
        new_referral = Referral(referrer_id=referred_by.id, referred_user_id=new_user.id, status='successful')
        db.session.add(new_referral)
        db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email_or_username = data.get('email_or_username')
    password = data.get('password')
    
    user = User.query.filter((User.email == email_or_username) | (User.username == email_or_username)).first()
    if not user or not bcrypt.check_password_hash(user.password_hash, password):
        return jsonify({"error": "Invalid credentials"}), 401
    
    access_token = create_access_token(identity=user.id)
    return jsonify({"token": access_token}), 200

@app.route('/api/referrals', methods=['GET'])
@jwt_required()
def get_referrals():
    user_id = get_jwt_identity()
    referrals = Referral.query.filter_by(referrer_id=user_id).all()
    return jsonify({"referrals": [{"id": r.referred_user_id, "date_referred": r.date_referred, "status": r.status} for r in referrals]}), 200

@app.route('/api/referral-stats', methods=['GET'])
@jwt_required()
def referral_stats():
    user_id = get_jwt_identity()
    count = Referral.query.filter_by(referrer_id=user_id).count()
    return jsonify({"referral_count": count}), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)