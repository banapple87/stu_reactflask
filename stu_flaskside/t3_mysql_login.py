# pip install pymysql

# CREATE DATABASE user_db;

# USE user_db;

# CREATE TABLE user (
#     id INT AUTO_INCREMENT PRIMARY KEY,
#     username VARCHAR(255) UNIQUE NOT NULL,
#     password VARCHAR(255) NOT NULL
# );


from flask import Flask, jsonify, request, session, redirect
from flask_session import Session
from flask_cors import CORS
import pymysql
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# CORS 설정 (flask_cors로 처리)
CORS(app, supports_credentials=True, resources={r"/*": {"origins": "http://localhost:3000"}})

app.config['SECRET_KEY'] = 'your_secret_key'  # 세션을 위한 비밀 키 설정
app.config['SESSION_TYPE'] = 'filesystem'  # 세션 저장소를 파일 시스템으로 설정
Session(app)

# MySQL 데이터베이스 연결 설정
db = pymysql.connect(
    host="10.104.24.229",  # MySQL 호스트
    user="reactone",  # MySQL 사용자
    password="reactone123",  # MySQL 비밀번호
    database="user_db",  # 사용할 데이터베이스 이름
    cursorclass=pymysql.cursors.DictCursor  # 결과를 딕셔너리로 받기 위해 설정
)
# print("db:", db)

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
    print("username:", username)
    print("hashed_password:", hashed_password)

    try:
        with db.cursor() as cursor:
            sql = "INSERT INTO user (username, password) VALUES (%s, %s)"
            cursor.execute(sql, (username, hashed_password))
            db.commit()
        return jsonify({'message': 'User registered successfully!'}), 201
    except pymysql.MySQLError as e:
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
        with db.cursor() as cursor:
            sql = "SELECT * FROM user WHERE username = %s"
            cursor.execute(sql, (username,))
            user = cursor.fetchone()

            if user and check_password_hash(user['password'], password):
                session['user'] = username  # 세션에 사용자 정보 저장
                return jsonify({'message': 'Login successful!', 'user': username})
            else:
                return jsonify({'message': 'Invalid credentials'}), 401
    except pymysql.MySQLError as e:
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

@app.route('/')
def home():
    return jsonify({'message': 'Welcome to the Flask server!'}), 200

if __name__ == '__main__':
    app.run(debug=True)
