from flask import Flask, jsonify, request, session
from flask_session import Session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# CORS 설정
CORS(app, supports_credentials=True, resources={r"/*": {"origins": "http://localhost:3000"}})

app.config['SECRET_KEY'] = 'your_secret_key'  # 세션을 위한 비밀 키 설정
app.config['SESSION_TYPE'] = 'filesystem'  # 세션 저장소를 파일 시스템으로 설정
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:1234@localhost/user_db'  # SQLAlchemy DB URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
Session(app)

# SQLAlchemy 데이터베이스 초기화
db = SQLAlchemy(app)

# 사용자 모델 정의
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# CORS preflight 요청에 대한 응답
def _build_cors_prelight_response():
    response = jsonify({'message': 'CORS preflight'})
    response.headers.add("Access-Control-Allow-Origin", "http://localhost:3000")
    response.headers.add("Access-Control-Allow-Headers", "Content-Type")
    response.headers.add("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
    response.headers.add("Access-Control-Allow-Credentials", "true")
    return response

# 회원가입 처리
@app.route('/api/register', methods=['POST', 'OPTIONS'])
def register():
    if request.method == 'OPTIONS':
        return _build_cors_prelight_response()

    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    hashed_password = generate_password_hash(password)

    try:
        # 새로운 사용자 생성 및 데이터베이스에 추가
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({'message': 'User registered successfully!'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Error occurred while registering'}), 500

# 로그인 처리
@app.route('/api/login', methods=['POST', 'OPTIONS'])
def login():
    if request.method == 'OPTIONS':
        return _build_cors_prelight_response()

    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    try:
        # 사용자 데이터베이스에서 사용자 찾기
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['user'] = username  # 세션에 사용자 정보 저장
            return jsonify({'message': 'Login successful!', 'user': username})
        else:
            return jsonify({'message': 'Invalid credentials'}), 401
    except Exception as e:
        return jsonify({'message': 'Error occurred during login'}), 500

# 로그아웃 처리
@app.route('/api/logout', methods=['POST', 'OPTIONS'])
def logout():
    if request.method == 'OPTIONS':
        return _build_cors_prelight_response()

    session.pop('user', None)  # 세션에서 사용자 정보 제거
    return jsonify({'message': 'Logout successful!'}), 200

# 인증된 사용자만 접근 가능
@app.route('/api/data', methods=['GET', 'OPTIONS'])
def get_data():
    if request.method == 'OPTIONS':
        return _build_cors_prelight_response()

    if 'user' in session:  # 로그인한 사용자인지 확인
        return jsonify({'message': f'Hello, {session["user"]}! This is your data.'})
    else:  # 로그인하지 않은 경우
        return jsonify({'message': 'Unauthorized'}), 401

if __name__ == '__main__':
    # 애플리케이션 시작 시 테이블 생성
    with app.app_context():
        db.create_all()
    app.run(debug=True)

# db.create_all()은 테이블이 이미 존재하는 경우에는 아무런 작업을 하지 않음, 테이블이 없는 경우에만 새로 생성
# 이미 테이블이 존재하고, 해당 테이블의 스키마를 수정하거나 기존 데이터베이스를 반영하려면 마이그레이션 도구(Flask-Migrate)를 사용.