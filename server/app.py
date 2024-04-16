#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        try:
            
            user = User(
                username=username,
                image_url=data.get('image_url', ''),
                bio=data.get('bio', '')
            )
            user.password_hash=password
            db.session.add(user)
            db.session.commit()
            session['user_id'] = user.id
            return {
                "id": user.id,
                "username": user.username,
                "image_url": user.image_url,
                "bio": user.bio
            }, 201
        except IntegrityError as e:
            db.session.rollback()
            return { "errors": [str(e)]}, 422


# class CheckSession(Resource):
#     def get(self):
#         user_id = session.get('user_id')
#         if not user_id:
#             return {}, 401 

#         user = User.query.filter_by(id=user_id).first()
#         if user is None:
#             return {}, 404  

#         return user.to_dict(), 200
        
class CheckSession(Resource):
    def get(self):
        user_id = session['user_id']
        if user_id:
            user = User.query.filter(user_id == User.id).first()
            print (user)
            
            return user.to_dict(), 200
        else:
            return {"error": "User not found"}, 401
class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return {"error": "Username and password are required"}, 400

        user = User.query.filter_by(username=username).first()

        if user and user.authenticate(password):
            session['user_id'] = user.id
            return {
                "id": user.id,
                "username": user.username,
                "image_url": user.image_url,
                "bio": user.bio
            }, 200
        else:
            return {"error": "Invalid username or password"}, 401
class Logout(Resource):
    def delete(self):
        if session["user_id"]:
            session["user_id"] = None
            return {}, 204
        else:
            return {"error": "Unauthorized access"}, 401


class RecipeIndex(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return {"error": "Unauthorized"}, 401

        try:
            recipes = Recipe.query.filter_by(user_id=user_id).all()
            return ([recipe.to_dict() for recipe in recipes]), 200
        except Exception as e:
            return {"errors": [str(e)]}, 422

    def post(self):
        user_id = session.get('user_id')
        if not user_id:
            return {"error": "Unauthorized"}, 401

        data = request.get_json()
        title = data.get('title')
        instructions = data.get('instructions')
        minutes_to_complete = data.get('minutes_to_complete')

        if not title or not instructions or not minutes_to_complete:
            return {"error": "Missing fields"}, 422

        try:
            recipe = Recipe(
                title=title,
                instructions=instructions,
                minutes_to_complete=minutes_to_complete,
                user_id=user_id
            )
            db.session.add(recipe)
            db.session.commit()
            return (recipe.to_dict()), 201
        except IntegrityError as e:
            db.session.rollback()
            return {"errors": [str(e)]}, 422
        except Exception as e:
            db.session.rollback()
            return {"errors": [str(e)]}, 422


api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)




# from sqlalchemy.orm import validates


# class User(db.Model):
#     __tablename__ = 'users'
#     id = Column(Integer, primary_key=True)
#     username = Column(String(50), unique=True, nullable=False)
#     email = Column(String(50), unique=True, nullable=False)


#     @validates('email')
#     def validate_email(self, key, email):
#         assert '@' in email, "Invalid email"
#         return email

