"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
import os
from flask import Flask, request, jsonify, url_for
from flask_migrate import Migrate
from flask_swagger import swagger
from flask_cors import CORS
from utils import APIException, generate_sitemap, token_required
from admin import setup_admin
import datetime
import jwt
from models import db, User
from werkzeug.security import generate_password_hash, check_password_hash
#from models import Person

app = Flask(__name__)
app.url_map.strict_slashes = False
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DB_CONNECTION_STRING')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
MIGRATE = Migrate(app, db)
db.init_app(app)
CORS(app)
setup_admin(app)

# Handle/serialize errors like a JSON object
@app.errorhandler(APIException)
def handle_invalid_usage(error):
    return jsonify(error.to_dict()), error.status_code

# generate sitemap with all your endpoints
@app.route('/')
def sitemap():
    return generate_sitemap(app)

@app.route('/user', methods=['GET'])
def handle_hello():

    response_body = {
        "msg": "Hello, this is your GET /user response "
    }

    return jsonify(response_body), 200

@app.route('/register', methods=['GET', 'POST'])
def signup_user():  
    data = request.get_json()  

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(id=data['id'], email=data['email'], password=hashed_password, is_active=data["is_active"]) 
    db.session.add(new_user)  
    db.session.commit()    

    return jsonify({'message': 'registered successfully'})

@app.route('/login', methods=['GET', 'POST'])  
def login_user(): 

    auth = request.authorization   

    if not auth or not auth.username or not auth.password:  
        return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})    

    user = User.query.filter_by(email=auth.username).first()   
        
    if check_password_hash(user.password, auth.password):  
        token = jwt.encode({'id': user.id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])  
        return jsonify({'token' : token.decode('UTF-8')}) 

    return make_response('could not verify',  401, {'WWW.Authentication': 'Basic realm: "login required"'}) 

@app.route('/users', methods=['GET'])
def get_all_users():  
   
   users = User.query.all() 

   result = []   

   for user in users:   
       user_data = {}   
       user_data['id'] = user.id  
       user_data['email'] = user.email 
       
       result.append(user_data)   

   return jsonify({'users': result})

# this only runs if `$ python src/main.py` is executed
if __name__ == '__main__':
    PORT = int(os.environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=PORT, debug=False)
