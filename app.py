from flask import Flask, request, jsonify
import os
from dotenv import load_dotenv
from flask_mail import Mail, Message
from jwt import encode, decode
import base64
from werkzeug.security import generate_password_hash, check_password_hash
import time
from datetime import timedelta
from flask import session, app

load_dotenv()
arr=[]
arr1=[]
active_user=[]
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
app.config['SECRET_KEY'] = 'xxxxxxxxx'

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
    active_user.append(username)
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
            link = encode({"username":username,"email": email,"action": "deactivate", "timestamp": int(time.time())}, os.getenv('JWT_SECRET_KEY'))
            activation_link = f"http://127.0.0.1:5000/deactivate?link={link}"
            msg = Message(subject='Unauthorized Access', sender=os.getenv('MAIL_USERNAME'), recipients=[email])
            msg.body = "Hey "+ username + " Your account is temporarily locked due to multiple login attempts. Click the link to deactivate your account:" + activation_link
            mail.send(msg)
            return jsonify({'message': 'Last attempt failed (unauthorized access), deactivation link sent to your email'}), 400
        else:
            return jsonify({'message': 'Incorrect password, try again'}), 400
    elif username not in active_user:
        return jsonify({'message': 'User is not activated'}), 400
    else:
        token = encode({"email": email,"action": "login", "timestamp": int(time.time())}, os.getenv('JWT_SECRET_KEY'))
        return jsonify({'message': 'Login successful','username':username,'email':email,'token': token}), 400
    
@app.route('/deactivate', methods=['GET'])
def deactivate():
    link = request.args.get('link')
    if link in arr1:
        User.is_valid=True
    else:
        User.is_valid=False
        arr1.append(link)
    if link and User.is_valid!=True:
            decoded_link = decode(link, os.getenv('JWT_SECRET_KEY'), algorithms=['HS256'])
            email = decoded_link.get('email')
            username=decoded_link.get('username')
            User.is_valid=True
            user = User.query.filter_by(email=email).first()
            if user:
                active_user.remove(username)
                return jsonify({'message':'Account deactivated successfully'})
            else:
                return jsonify({'message': 'User does not exist'}), 400
    else:
        return jsonify({'message':'Link is not valid'})
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
        link = encode({"username":username,"email": email,"password":password,"action": "activate", "timestamp": int(time.time())}, os.getenv('JWT_SECRET_KEY'))
        activation_link = f"http://127.0.0.1:5000/activate?link={link}"
        msg = Message(subject='Activate your Account', sender=os.getenv('MAIL_USERNAME'), recipients=[email])
        msg.body = "Hey,"+ username + "To activate your account. Click the link : " + activation_link
        mail.send(msg)
        return jsonify({'message': 'activation link sent to your email'}), 400

@app.route('/activate',methods=['GET'])
def activate():
    res = str(session.items())
    link = request.args.get('link')
    if link in arr:
        User.is_valid=False
    else:
        User.is_valid=True
        arr.append(link)
    if link and User.is_valid!=False:
        decoded_link = decode(link, os.getenv('JWT_SECRET_KEY'), algorithms=['HS256'])
        email = decoded_link.get('email')
        username=decoded_link.get('username')
        password=decoded_link.get('password')
        User.is_valid=False
        user = User.query.filter_by(email=email,password_hash=password).first()
        if user :
            if user:
                active_user.append(username)
                return jsonify({'message': 'Account activated successfully'}), 200
        else:
            return jsonify({'message': 'User does not exist'}), 400
    else:
        return jsonify({'message': 'link is not valid'}), 400


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