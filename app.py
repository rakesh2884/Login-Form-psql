from flask import Flask, request, jsonify,redirect
import os
from dotenv import load_dotenv
from flask_mail import Mail, Message
from jwt import encode,decode
import base64

load_dotenv()
app=Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI']= os.getenv('SQLALCHEMY_DATABASE_URI')
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
@app.route('/register',methods=['GET','POST'])
def register():
    data = request.get_json()
    username = data['username']
    password = data['password']
    email=data['email']
    user = User(username=username,password_hash=password,email=email)
    existing_user= User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({'message':'User already exist'}),201
    user.save()
    return jsonify({'message': 'User registered successfully'}),201

@app.route('/login',methods=['GET','POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']
    email=data['email']
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'message':'user not exist'})
    elif user.password_hash!=password:
        return jsonify({'message':'Incorrect password try again'})
    else:
        return jsonify({'message':'login successful'})
@app.route('/login_attempt_2',methods=['GET','POST'])
def login_2():
    data = request.get_json()
    username = data['username']
    password = data['password']
    email=data['email']
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'message':'user not exist'})
    elif user.password_hash!=password:
        return jsonify({'message':'Incorrect password try again'})
    else:
        return jsonify({'message':'login successful'})
@app.route('/login_attempt_last',methods=['GET','POST'])
def login_last():
    data = request.get_json()
    username = data['username']
    password = data['password']
    email=data['email']
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'message':'user not exist'})
    elif user.password_hash!=password:
        token = encode({"email": email,"username":username}, os.getenv('JWT_SECRET_KEY'))
        sample_string = token
        sample_string_bytes = sample_string.encode("ascii")      
        base64_bytes = base64.b64encode(sample_string_bytes) 
        base64_string = base64_bytes.decode("ascii") 
        msg = Message(subject=' Unauthorized access', sender=os.getenv('MAIL_USERNAME'), recipients=[email])
        msg.body = "Hey, "+username+" someone try to access your account. Plz change your password or deactivate your account.\nClick on the following link to deactivate your account.\n"+base64_string
        mail.send(msg)
        return jsonify({'message': 'Last attempt Failed (unauthorized access)'}),201
    else:
        return jsonify({'message':'login successful'})
@app.route('/deactivate',methods=['GET','POST'])
def deactivate():
    data = request.get_json()
    username = data['username']
    password = data['password']
    EMail=data['email']
    d_link=data['d_link']
    base64_string =d_link
    base64_bytes = base64_string.encode("ascii")     
    sample_string_bytes = base64.b64decode(base64_bytes) 
    sample_string = sample_string_bytes.decode("ascii") 
    Decrypt = decode(sample_string, os.getenv('JWT_SECRET_KEY'),algorithms=['HS256'])
    email = Decrypt["email"]
    user_n=Decrypt["username"]
    if EMail==email and username==user_n:
        user= User.query.filter_by(username=username,password_hash=password).first()
        if user:
            user.remove()
            return jsonify({'message':'account deactivated successfully'})
        else:
            return jsonify({'message':'user not exist'})
    else:
        return jsonify({'message':'invalind link'})

        
@app.route('/display',methods=['GET','POST'])
def display():
    users=User.query.all()
    arr=[]
    for user in users:
        lst=([{'id': user.id, 'username':user.username,'email':user.email}])
        arr.append(lst)
    return ({'users': arr}),201
if __name__=='__main__':
    app.run(debug=True)