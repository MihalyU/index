from flask import Flask, request, jsonify
from flask_restful import Api, Resource
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
api = Api(app)


app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:pRoLyjCzIkDyKuhfxCAwxrOmsJvnFbIC@interchange.proxy.rlwy.net:55539/railway'
app.config['JWT_SECRET_KEY'] = 'supersecretkey'

db = SQLAlchemy(app)
jwt = JWTManager(app)



class User(db.Model):
    __tablename__ = 'users'  # ✅ avoid reserved keyword "user"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)


    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), unique=True, nullable=False)
    price = db.Column(db.Float, nullable=False)



def is_admin(user_id):
    user = User.query.get(user_id)
    return user.is_admin if user else False



class Register(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        is_admin = data.get('is_admin', False)

        if not username or not password:
            return {'message': 'Username and password required'}, 400

        if User.query.filter_by(username=username).first():
            return {'message': 'User already exists'}, 400

        new_user = User(username=username, is_admin=is_admin)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        access_token = create_access_token(identity=new_user.id)
        return {'access_token': access_token}, 201


class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        user = User.query.filter_by(username=username).first()
        if not user or not user.check_password(password):
            return {'message': 'Invalid credentials'}, 401

        access_token = create_access_token(identity=user.id)
        return {'access_token': access_token}, 200


class AdminLogin(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        user = User.query.filter_by(username=username, is_admin=True).first()
        if not user or not user.check_password(password):
            return {'message': 'Invalid admin credentials'}, 401

        access_token = create_access_token(identity=user.id)
        return {'access_token': access_token}, 200


class AdminCourse(Resource):
    @jwt_required()
    def post(self):
        user_id = get_jwt_identity()
        if not is_admin(user_id):
            return {'message': 'Admins only'}, 403

        data = request.get_json()
        title = data.get('title')
        price = data.get('price')

        if not title or price is None:
            return {'message': 'Title and price required'}, 400

        if Course.query.filter_by(title=title).first():
            return {'message': 'Course already exists'}, 400

        new_course = Course(title=title, price=price)
        db.session.add(new_course)
        db.session.commit()
        return {'message': 'Course added'}, 201

    @jwt_required()
    def put(self):
        user_id = get_jwt_identity()
        if not is_admin(user_id):
            return {'message': 'Admins only'}, 403

        data = request.get_json()
        title = data.get('title')
        price = data.get('price')

        course = Course.query.filter_by(title=title).first()
        if not course:
            return {'message': 'Course not found'}, 404

        course.price = price
        db.session.commit()
        return {'message': 'Course price updated'}, 200

    @jwt_required()
    def delete(self):
        user_id = get_jwt_identity()
        if not is_admin(user_id):
            return {'message': 'Admins only'}, 403

        data = request.get_json()
        title = data.get('title')

        course = Course.query.filter_by(title=title).first()
        if not course:
            return {'message': 'Course not found'}, 404

        db.session.delete(course)
        db.session.commit()
        return {'message': 'Course deleted'}, 200


class CourseList(Resource):
    def get(self):
        courses = Course.query.all()
        return [{'title': c.title, 'price': c.price} for c in courses], 200



api.add_resource(Register, '/register')
api.add_resource(Login, '/login')
api.add_resource(AdminLogin, '/admin/login')     
api.add_resource(CourseList, '/courses')          
api.add_resource(AdminCourse, '/admin/courses')   



if __name__ == '__main__':
    import os
    os.makedirs('instance', exist_ok=True)  

    with app.app_context():
        db.create_all()
    app.run(debug=True)

