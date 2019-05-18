from flask import Flask, jsonify, request, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import datetime
import jwt

app = Flask(__name__)

app.config['SECRET_KEY'] = 'mysecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////details.db'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # get token from authorization header
        token = request.headers.get('Authorization')

        if not token:
            return jsonify({'message':'Token is missing!'}), 404

        # verify if token is valid
        try:
            decoded = jwt.decode(token, app.config['PUBLIC_KEY_RSA'])

        except:
            return jsonify({'message':'Token is invalid'}), 404

        return f(*args, **kwargs)

    return decorated        

@app.route('/unprotected', methods = ["GET"])
def unprotected():
    return ''

@app.route('/protected', methods = ["GET"])
def protected():
    return ''

@app.route('/signin', methods = ["POST"])
def signin():
    data = request.get_json()
    name = data['name']
    password = data['password']
    
    auth_user = User.query.filter_by(name = name, password = password).first()

    #if not auth_user:
    #    return make_response('Could not verify', 401).............

    return ''

# register user
@app.route('/signup', methods = ["POST"])
def signup():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(name=data['name'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'New User Created!'})

if __name__ =='__main__':
    app.run(debug=True)