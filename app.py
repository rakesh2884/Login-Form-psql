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
            token = encode({"email": email,"password":password}, os.getenv('JWT_SECRET_KEY'))
            sample_string = token
            sample_string_bytes = sample_string.encode("ascii") 
            base64_bytes = base64.b64encode(sample_string_bytes) 
            base64_string = base64_bytes.decode("ascii") 
            msg = Message(subject='Unauthorized_access', sender=os.getenv('MAIL_USERNAME'), recipients=[email])
            msg.body = "Hey, "+username+" please verify the mail\n"+base64_string
            mail.send(msg)
            return jsonify({'message': 'Last attempt failed (unauthorized access), deactivation link sent to your email'}), 400
        else:
            return jsonify({'message': 'Incorrect password, try again'}), 400
    elif not user.is_active:
        return jsonify({'message': 'User is not activated'}), 400
    else:
        return jsonify({'message': 'Login successful'}), 200
    
@app.route('/deactivate', methods=['GET',"POST"])
def deactivate():
    data=request.get_json()
    username=data['username']
    password=data['password']
    EMail=data['email']
    d_link=data['d_link']
    base64_string =d_link
    base64_bytes = base64_string.encode("ascii") 
    sample_string_bytes = base64.b64decode(base64_bytes) 
    sample_string = sample_string_bytes.decode("ascii") 
    Decrypt = decode(sample_string, os.getenv('JWT_SECRET_KEY'),algorithms=['HS256'])
    email = Decrypt["email"]
    passw=Decrypt["password"]
    if EMail==email and password==passw:
        user=User.query.filter_by(username=username,password_hash=password).first()
        if user:
            user.deactivate()
            return jsonify({'message':'account deactivated successfully'})
        else:
            return jsonify({'message':'user not exist'})
    else:
        return jsonify({'message':'inavlid link'}) 

@app.route('/get_activate_link',methods=['GET','POST'])
def get_activate_link():
    data = request.get_json()
    username = data['username']
    password = data['password']
    email = data['email']
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'message': 'User does not exist'}), 400
    else:
        token = encode({"email": email,"password":password}, os.getenv('JWT_SECRET_KEY'))
        sample_string = token
        sample_string_bytes = sample_string.encode("ascii") 
        base64_bytes = base64.b64encode(sample_string_bytes) 
        base64_string = base64_bytes.decode("ascii") 
        msg = Message(subject='activation link', sender=os.getenv('MAIL_USERNAME'), recipients=[email])
        msg.body = "Hey, "+username+" please verify the mail\n"+base64_string
        mail.send(msg)
        return jsonify({'message': 'activation link sent to your email'}), 400


@app.route('/activate',methods=['GET','POST'])
def activate():
    data=request.get_json()
    username=data['username']
    password=data['password']
    EMail=data['email']
    d_link=data['d_link']
    base64_string =d_link
    base64_bytes = base64_string.encode("ascii") 
    sample_string_bytes = base64.b64decode(base64_bytes) 
    sample_string = sample_string_bytes.decode("ascii") 
    Decrypt = decode(sample_string, os.getenv('JWT_SECRET_KEY'),algorithms=['HS256'])
    email = Decrypt["email"]
    passw=Decrypt["password"]
    if EMail==email and password==passw:
        user=User.query.filter_by(username=username,password_hash=password).first()
        if user:
            user.activate()
            return jsonify({'message':'account activated successfully'})
        else:
            return jsonify({'message':'user not exist'})
    else:
        return jsonify({'message':'inavlid link'}) 


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
