from flask import Flask, request, jsonify
import os
from dotenv import load_dotenv
from flask_mail import Mail, Message
from jwt import encode, decode
import base64
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy


load_dotenv()
app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = os.getenv('MAIL_PORT')
app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL')
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS')
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

mail = Mail(app)
from model import User

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data['username']
    password = data['password']
    email = data['email']
    user = User(username=username, email=email,password_hash=password)
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({'message': 'User already exists'}), 400
    user.save()
    return jsonify({'message': 'User registered successfully'}), 201

login_attempts = {}
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']
    email = data['email']
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'message': 'User does not exist'}), 400
    elif user.password_hash != password:
        if username in login_attempts:
            login_attempts[username] += 1
        else:
            login_attempts[username] = 1

        if login_attempts[username] >= 3:
            link = encode({"email": email}, os.getenv('JWT_SECRET_KEY'))
            activation_link = f"http://127.0.0.1:5000/deactivate?link={link}"
            msg = Message(subject='Unauthorized Access', sender=os.getenv('MAIL_USERNAME'), recipients=[email])
            msg.body = f"Hey, {username}! Your account is temporarily locked due to multiple login attempts. Click the link to deactivate your account: {activation_link}"
            mail.send(msg)
            return jsonify({'message': 'Last attempt failed (unauthorized access), deactivation link sent to your email'}), 400
        else:
            return jsonify({'message': 'Incorrect password, try again'}), 400
    elif User.is_active==False:
        return jsonify({'message': 'User is not activated'}), 400
    else:
        return jsonify({'message': 'Login successful'}), 200
    
@app.route('/deactivate', methods=['GET'])
def deactivate():
    link = request.args.get('link')
    if link:
        decoded_link = decode(link, os.getenv('JWT_SECRET_KEY'), algorithms=['HS256'])
        email = decoded_link.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            User.is_active=False
            return jsonify({'message': 'Account deactivated successfully'}), 200
        else:
            return jsonify({'message': 'User does not exist'}), 400
    else:
        return jsonify({'message': 'link not provided'}), 400
@app.route('/get_activate',methods=['GET','POST'])
def get_activate():
    data = request.get_json()
    username = data['username']
    password = data['password']
    email = data['email']
    user = User.query.filter_by(username=username,password_hash=password).first()
    if not user:
        return jsonify({'message': 'User does not exist'}), 400
    else:
        link = encode({"email": email,"password":password}, os.getenv('JWT_SECRET_KEY'))
        activation_link = f"http://127.0.0.1:5000/activate?link={link}"
        msg = Message(subject='Activate your Account', sender=os.getenv('MAIL_USERNAME'), recipients=[email])
        msg.body = f"Hey, {username} To activate your account. Click the link : {activation_link}"
        mail.send(msg)
        return jsonify({'message': 'activation link sent to your email'}), 400

@app.route('/activate',methods=['GET'])
def activate():
    link = request.args.get('link')
    if link:
        decoded_link = decode(link, os.getenv('JWT_SECRET_KEY'), algorithms=['HS256'])
        email = decoded_link.get('email')
        password=decoded_link.get('password')
        user = User.query.filter_by(email=email,password_hash=password).first()
        if user:
            User.is_active=True
            return jsonify({'message': 'Account activated successfully'}), 200
        else:
            return jsonify({'message': 'User does not exist'}), 400
    else:
        return jsonify({'message': 'link not provided'}), 400


@app.route('/display',methods=['GET','POST'])
def display():
    users=User.query.all()
    arr=[]
    for user in users:
        lst=([{'id': user.id, 'username':user.username,'email':user.email}])
        arr.append(lst)
    return ({'users': arr}),201
if __name__ == '__main__':
    app.run(debug=True)
