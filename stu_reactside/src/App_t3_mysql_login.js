import React, { useState } from 'react';
import axios from 'axios';

const App = () => {
  const [message, setMessage] = useState('');
  const [username, setUsername] = useState('june8');
  const [password, setPassword] = useState('1234');
  const [loggedIn, setLoggedIn] = useState(false);
  const [loggedInUser, setLoggedInUser] = useState('');

  // Axios에서 세션 쿠키를 전달할 수 있도록 설정
  axios.defaults.withCredentials = true;

  // 회원가입 요청
  const register = () => {
    axios.post('http://localhost:5000/api/register', { username, password })
      .then(response => {
        console.log(response.data.message);
      })
      .catch(error => {
        console.error('Registration failed:', error.response.data.message);
      });
  };

  // 로그인 요청
  const login = () => {
    axios.post('http://localhost:5000/api/login', { username, password })
      .then(response => {
        setLoggedIn(true);
        setLoggedInUser(response.data.user);
        console.log(response.data.message);
      })
      .catch(error => {
        console.error('Login failed:', error.response.data.message);
      });
  };

  // 로그아웃 요청
  const logout = () => {
    axios.post('http://localhost:5000/api/logout')
      .then(response => {
        setLoggedIn(false);
        setLoggedInUser('');
        console.log(response.data.message);
      })
      .catch(error => {
        console.error('Logout failed:', error.response.data.message);
      });
  };

  // 로그인한 사용자만 접근할 수 있는 API 호출 (GET)
  const getData = () => {
    axios.get('http://localhost:5000/api/data')
      .then(response => {
        setMessage(response.data.message);
      })
      .catch(error => {
        console.error('Unauthorized or error fetching data:', error.response.data.message);
      });
  };

  return (
    <div>
      {!loggedIn ? (
        <div>
          <div>
            <label>
              ID 
              <input
                type="text"
                placeholder="Username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
              />
            </label>
          </div>

          <div>
            <label>PW 
              <input
                type="password"
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </label>
          </div>

          <h2>Register</h2>
          <button onClick={register}>Register</button>

          <h2>Login</h2>
          <button onClick={login}>Login</button>
        </div>
      ) : (
        <div>
          <h2>Welcome, {loggedInUser}!</h2> 
          <button onClick={getData}>Get Data</button>
          <button onClick={logout}>Logout</button>
          {message && <p>{message}</p>}
        </div>
      )}
    </div>
  );
};

export default App;
