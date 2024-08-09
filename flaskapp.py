import numpy as np
# import tensorflow as tf
# import tensorflow_hub as hub
# from tensorflow import keras
from flask_jwt_extended import JWTManager, create_access_token
import bcrypt
from pymongo import ReturnDocument
import re
import jwt
import json
from bson.objectid import ObjectId
from bson import json_util
from bson.json_util import dumps, loads
from functools import wraps
from flask_cors import CORS, cross_origin
from flask.helpers import url_for
from flask_pymongo import PyMongo
import datetime
from flask import Flask, request, Response, jsonify, session, redirect
app = Flask(__name__)
jwt = JWTManager(app)

CORS(app)


app.config['MONGO_URI']='mongodb+srv://nadeemparokkot:u52wdDkDWj39fzRO@cluster0.nyovl2p.mongodb.net/EwebsiteDB?retryWrites=true&w=majority&appName=Cluster0'
mongo = PyMongo(app)

app.secret_key = 'super secret key'
app.config["JWT_SECRET_KEY"] = "this-is-secret-key"



@app.route('/testpage')
def testpage():
    return jsonify(message='all good!')


@app.route("/adminRegister", methods=['POST', 'GET'])
def userRegister():
    if request.method == 'POST':
        allUsers = mongo.db.users
        user = allUsers.find_one({'email': request.json['email']})
        companyName = allUsers.find_one({'companyName': request.json['companyName']})
        phone = allUsers.find_one({'phone': request.json['phone']})

        if user:
            return jsonify(message='Email already exists'), 401
        if companyName:
            return jsonify(message='Username already exists'), 401
        if phone:
            return jsonify(message='Phone Number already exists'), 401

        if request.json['password'] != request.json['cpassword']:
            return jsonify(message='Password Not Matching!'), 401

        hashpw = bcrypt.hashpw(
            request.json['password'].encode('utf-8'), bcrypt.gensalt())

        hashCpw = bcrypt.hashpw(
            request.json['cpassword'].encode('utf-8'), bcrypt.gensalt())

        access_token = create_access_token(identity=request.json['email'])

        allUsers.insert_one({
            'email': request.json['email'],
            'password': hashpw,
            'cpassword': hashCpw,
            "companyName": request.json['companyName'],
            "phone": request.json['phone'],
            'tokens': [
                {
                    'token': str(access_token)
                }
            ]
        })

        session['email'] = request.json['email']
        return jsonify(token=str(access_token)), 201



@app.route("/userLogin", methods=['POST'])
def userLogin():
    allUsers = mongo.db.users
    user = allUsers.find_one({'email': request.json['email']})

    if user:
        # Check if the provided password matches the stored hashed password
        if bcrypt.checkpw(request.json['password'].encode('utf-8'), user['password']):
            access_token = create_access_token(identity=request.json['email'])
            user['tokens'].append({'token': str(access_token)})
            allUsers.update_one(
                {'_id': user['_id']}, 
                {'$set': {'tokens': user['tokens']}}
            )
            return jsonify(token=str(access_token)), 201
        else:
            return jsonify(message='Invalid Username/Password'), 401
    return jsonify(message='User not found'), 404


@app.route("/getUserData", methods=['POST'])
def getUserData():

    allUsers = mongo.db.users
    # user = allUsers.find_one({'tokens.token': request.json['auth']})
    user = dumps(
        list(allUsers.find({'tokens.token': request.json['auth']})), indent=2)

    if user:
        user = json.loads(user)
        return jsonify(user), 201

    return jsonify(message='Something went wrong'), 401


@app.route("/logoutUser", methods=['POST'])
def logoutUser():
    allUsers = mongo.db.users
    auth_token = request.json.get('auth')  # Get the token from the request
    user = allUsers.find_one({'tokens.token': auth_token})

    if user:
        # Specify the filter and update operation
        result = allUsers.update_one(
            {'_id': user['_id']},  # Filter by user ID
            {'$set': {'tokens': []}}  # Update operation: set tokens to an empty list
        )
        
        if result.modified_count > 0:
            return jsonify(message='Logout Successfully!'), 200  # Changed to 200 for success
        else:
            return jsonify(message='Logout Failed!'), 400  # Indicate failure in case of no modification
    
    return jsonify(message='User not found!'), 404  # Indicate user not found

# admin api


if __name__ == '__main__':

    app.run(debug=True)