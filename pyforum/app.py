from flask import Flask, request, jsonify, render_template,redirect,url_for,session
from flask_bcrypt import Bcrypt
import sqlite3

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "12345678iuhgvcjhgvhkn"

@app.route('/')
def main():
    return render_template('register.html')

def init_db():
    with sqlite3.connect('forum.db') as conn:
        cursor = conn.cursor()
        # Users Table
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        # Queries Table
        cursor.execute('''CREATE TABLE IF NOT EXISTS queries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            question TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )''')
        # Replies Table
        cursor.execute('''CREATE TABLE IF NOT EXISTS replies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            query_id INTEGER,
            user_id INTEGER,
            reply TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (query_id) REFERENCES queries(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )''')

init_db()

@app.route('/register', methods=['POST','GET'])
def register():
    if request.method == 'POST':
        # Get form data
        username = request.form['username']
        password = request.form['password']
        

        # Hash the password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        try:
            with sqlite3.connect('forum.db') as conn:
                cursor = conn.cursor()
                # Insert user into the database
                cursor.execute('INSERT INTO users (username, password, type) VALUES (?, ?, ?)', (username, hashed_password, "User"))
                conn.commit()
                return redirect(url_for('login'))  # Redirect to login page after registration
        except sqlite3.IntegrityError:
            return "Username already exists. Please choose a different username."
    return render_template('register.html')

@app.route('/create_admin', methods=['POST'])
def create_admin():
    username = request.form['username']
    password = request.form['password']

    # Hash the password
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    try:
        with sqlite3.connect('forum.db') as conn:
            cursor = conn.cursor()

            # Insert admin user into the database
            cursor.execute(
                'INSERT INTO users (username, password, type) VALUES (?, ?, ?)',
                (username, hashed_password, 'Admin')
            )
            conn.commit()  # Commit the changes
            return render_template(
                'create_admin.html', message="Admin account created successfully!"
            )
    except sqlite3.IntegrityError:
        # Handle username already exists
        return render_template(
            'create_admin.html',
            message="Username already exists. Please choose a different username."
        )
    except Exception as e:
        # Handle unexpected errors
        return render_template(
            'create_admin.html',
            message=f"An unexpected error occurred: {str(e)}"
        )

    # Fallback message if none of the above conditions are met
    return render_template('create_admin.html', message="An unknown error occurred.")

    


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']

        with sqlite3.connect('forum.db') as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()

            # Check if user exists and the password matches
            if user and bcrypt.check_password_hash(user[2], password):
                session['user_id'] = user[0]
                session['user_role'] = user[4]  # Store role for later use
                if user[4] == 'Admin':
                    return redirect(url_for('admin'))
                elif user[4] == 'User':
                    return redirect(url_for('get_queries'))  # Redirect to query page
            
            # If authentication fails
            return render_template('login.html', error="Invalid username or password.")
    
    # Render login form for GET requests
    return render_template('login.html')



@app.route('/post_query', methods=['POST'])
def post_query():
    
    user_id = session.get('user_id')
    question = request.form['enter_query']
    try:

        with sqlite3.connect('forum.db') as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO queries (user_id, question) VALUES (?, ?)', (user_id, question))
            conn.commit()
        return render_template('create.html',message = "Queery posted successfully")
                
    except Exception as e:
        return render_template('create.html', message=f"Error in posting query: {str(e)}")

@app.route('/reply_query', methods=['POST'])
def reply_query():

    user_id = session.get('user_id')
    data = request.json
    query_id = data['query_id']
    reply = data['reply']
    with sqlite3.connect('forum.db') as conn:
        cursor = conn.cursor()
        cursor.execute('INSERT INTO replies (query_id, user_id, reply) VALUES (?, ?, ?)', (query_id, user_id, reply))
        conn.commit()
        return jsonify({'message': 'Reply posted successfully'}), 201

@app.route('/get_queries', methods=['GET'])
def get_queries():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    with sqlite3.connect('forum.db') as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()

        cursor.execute('''SELECT q.id, q.question, u.username, q.created_at 
                          FROM queries q 
                          JOIN users u ON q.user_id = u.id''')
        queries = cursor.fetchall()
        
        query_list = []
        for query in queries:
            query_id, question, username, created_at = query
            cursor.execute('''SELECT r.reply, u.username, r.created_at 
                              FROM replies r 
                              JOIN users u ON r.user_id = u.id 
                              WHERE r.query_id = ?''', (query_id,))
            replies = cursor.fetchall()
            query_list.append({
                'query_id': query_id,
                'question': question,
                'username': username,
                'created_at': created_at,
                'replies': [{'reply': r[0], 'username': r[1], 'created_at': r[2]} for r in replies]
            })

    if request.headers.get('Accept') == 'application/json':
        return jsonify(query_list)

    return render_template('get_queries.html', user_id=user_id, username=user[0], queries=query_list)

@app.route('/logout')
def logout():
    session.clear()
    return render_template('logout.html')
@app.route('/create_query')
def create_query():
    return render_template('create.html')

@app.route('/create_admin_account_page')
def createAdmin():
    if session.get('user_role') == "Admin":
        return render_template('create_admin.html')
    else:
        return redirect(url_for('login'))

@app.route('/delete_user', methods = ['GET'])
def delete_user():
    username =request.args.get('id')
    try:
        with sqlite3.connect('forum.db') as conn:
            cursor = conn.cursor()
            cursor.execute('Delete From users where username = ?',(username,))
            conn.commit()
        return(redirect(url_for('show_users')))
    except Exception as e:
        return f"An error has occured: {str(e)}",500

@app.route('/show_users')
def show_users():
    conn = sqlite3.connect("forum.db")
    cursor = conn.cursor()
    cursor.execute("Select * from users")
    users = cursor.fetchall()
    return render_template("delete_account.html",users=users)

@app.route('/show_query_list', methods=['GET', 'POST'])
def show_query_list():
    if session.get('user_role') == "Admin":
        conn = sqlite3.connect('forum.db')
        cursor = conn.cursor()

        # Check if there is a search term
        search_username = request.args.get('user', '').strip()

        if search_username:
            # Fetch user_id for the searched username
            cursor.execute("SELECT id FROM users WHERE username = ?", (search_username,))
            user = cursor.fetchone()
            
            if user:  # If user is found, fetch their queries
                user_id = user[0]
                cursor.execute("SELECT * FROM queries WHERE user_id = ?", (user_id,))
                queries = cursor.fetchall()
            else:
                queries = []  # No queries found if username does not exist
        else:
            # Fetch all queries if no search term is provided
            cursor.execute("SELECT * FROM queries")
            queries = cursor.fetchall()

        # Prepare a list to store queries with usernames
        query_list = []
        for query in queries:
            # Fetch the username for the corresponding user_id
            cursor.execute("SELECT username FROM users WHERE id = ?", (query[1],))
            username = cursor.fetchone()
            
            # Append the query details along with the username
            if username:  # Check if a username is found
                query_list.append({
                    'query_id': query[0],
                    'user_id': query[1],
                    'username': username[0],  # Extract the username string
                    'question': query[2],
                    'created_at': query[3]
                })

        conn.close()

        # Pass the query_list to the template for display
        return render_template('delete_query.html', queries=query_list, search_username=search_username)
    else:
        session.clear()
        return redirect(url_for('login'))

    

@app.route('/delete_query',methods = ['GET'])
def delete_query():
    query_id=request.args.get('id')
    try:
        with sqlite3.connect('forum.db') as conn:
            cursor = conn.cursor()
            cursor.execute("Delete from queries where id = ?",(query_id,))
            return redirect(url_for('show_query_list'))
    except Exception as e:
        return f"An error has occured: {str(e)}",500
        

@app.route('/admin')
def admin():
    if session.get('user_role') == "Admin":
        return render_template('admin.html')
    else:
        return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
