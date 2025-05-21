from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/')
def home():
    return '<a href="/login">Login</a>'

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        try:
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            query = "SELECT * FROM users WHERE username=? AND password=?"
            cursor.execute(query, (username, password))
            user = cursor.fetchone()
            conn.close()
        except Exception as e:
            return f"Database error: {e}"

        if user:
            return f"Welcome, {username}!"
        else:
            return "Invalid credentials"

    return '''
    <form method="post">
        Username: <input name="username"><br>
        Password: <input name="password" type="password"><br>
        <input type="submit" value="Login">
    </form>
    '''

if __name__ == '__main__':
    app.run()
