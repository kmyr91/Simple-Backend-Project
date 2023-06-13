from flask import Flask, request, jsonify
from sqlalchemy import Column, Integer, String, Boolean, create_engine, ForeignKey
from sqlalchemy.orm import Session, sessionmaker, relationship
from sqlalchemy.ext.declarative import declarative_base
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_required, login_user, current_user
import logging
logging.basicConfig(filename='error.log', level=logging.DEBUG)
from flask_cors import CORS
from flask import send_from_directory

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'Canada0782'
app.debug = True

Base = declarative_base()



class Task(Base):
    __tablename__ = 'tasks'
    id = Column(Integer, primary_key=True)
    title = Column(String(100), nullable=False)
    description = Column(String(255))
    done = Column(Boolean, default=False)
    user_id = Column(Integer, ForeignKey('users.id'))


class User(Base, UserMixin):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    email = Column(String(100), unique=True)
    password = Column(String(256))
    active = Column(Boolean, default=True)
    tasks = relationship('Task', backref='user')

    def get_id(self):
        return (self.id)

engine = create_engine('mysql+mysqlconnector://bcproject:Chester5$@bcproject.mysql.database.azure.com/bcproject')
Session = sessionmaker(bind=engine)
Base.metadata.create_all(engine)


login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    session = Session()
    return session.query(User).get(int(user_id))

@login_manager.unauthorized_handler
def unauthorized():
    return jsonify({'error': 'Unauthorized access'}), 401

@app.route('/login', methods=['POST'])

@app.route('/login', methods=['POST'])
def login():
    app.logger.info('Received login request')

    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    session = Session()
    user = session.query(User).filter(User.email == email).first()
    session.close()

    if user is None:
        print("User is None")
        app.logger.info('Invalid username')
        return jsonify({'error': 'Invalid username'}), 400

    if user.password is None:
        print("Password is None")
        app.logger.info('No password for this user')
        return jsonify({'error': 'No password for this user'}), 400


    try:
        if not check_password_hash(user.password.decode('utf-8'), password):
            app.logger.info('Invalid password')
            return jsonify({'error': 'Invalid password'}), 400
    except Exception as e:
        print("Error checking password: ", e)

    login_user(user, remember=True)

    if current_user.is_authenticated:
        app.logger.info('User logged in successfully')
        return jsonify({'message': 'Logged in successfully'}), 200
    else:
        app.logger.error('Login unsuccessful')
        return jsonify({'error': 'Login unsuccessful'}), 400


@app.route('/home.html')
def home():
    return send_from_directory('static', 'home.html')  # Assuming 'home.html' is in a 'static' directory

@app.route('/tasks_page')
def tasks_page():
    return app.send_static_file('tasks.html')   

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    print(f'Received data: {data}')  # debug print

    email = data.get('email')
    password = data.get('password')
    session = Session()
    user = session.query(User).filter(User.email == email).first()
    if user is not None:
        session.close()
        return jsonify({'error': 'User already exists'}), 400
    hashed_password = generate_password_hash(password)
    new_user = User(email=email, password=hashed_password, active=True)
    session.add(new_user)
    session.commit()
    session.close()
    return jsonify({'message': 'User created'}), 201


@app.route('/tasks', methods=['POST'])
@login_required
def create_task():
    data = request.get_json()
    new_task = Task(
        title=data.get('title', ''),
        description=data.get('description', ''),
        done=data.get('done', False),
        user_id=current_user.id
    )
    session = Session()
    session.add(new_task)
    session.commit()
    session.close()
    return jsonify({"message": "Task created"}), 201

@app.route('/tasks', methods=['GET'])
@login_required
def get_tasks():
    session = Session()
    tasks = session.query(Task).filter(Task.user_id == current_user.id).all()
    task_list = [{"id": task.id, "title": task.title, "description": task.description, "done": task.done} for task in tasks]
    session.close()
    return jsonify(task_list), 200

@app.route('/tasks/<int:task_id>', methods=['GET'])
@login_required
def get_task(task_id):
    session = Session()
    task = session.query(Task).filter(Task.id == task_id).first()
    if task is None:
        session.close()
        return jsonify({'error': 'Task not found'}), 404
    task_data = {
        "id": task.id,
        "title": task.title,
        "description": task.description,
        "done": task.done
    }
    session.close()
    return jsonify(task_data), 200

@app.route('/tasks/<int:task_id>', methods=['PUT'])
@login_required
def update_task(task_id):
    session = Session()
    task = session.query(Task).filter(Task.id == task_id).first()
    if task is None:
        session.close()
        return jsonify({'error': 'Task not found'}), 404
    data = request.get_json()
    task.title = data.get('title', task.title)
    task.description = data.get('description', task.description)
    task.done = data.get('done', task.done)
    session.commit()
    session.close()
    return jsonify({"message": "Task updated"}), 200

@app.route('/tasks/<int:task_id>', methods=['DELETE'])
@login_required
def delete_task(task_id):
    session = Session()
    task = session.query(Task).filter(Task.id == task_id).first()
    if task is None:
        session.close()
        return jsonify({'error': 'Task not found'}), 404
    session.delete(task)
    session.commit()
    session.close()
    return jsonify({"message": "Task deleted"}), 200

if __name__ == '__main__':
    logging.basicConfig(filename='demo.log', level=logging.DEBUG)
    app.run(debug=True)
