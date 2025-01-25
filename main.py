import json
from flask.__init__ import Flask, render_template, request, redirect, url_for, flash, session
from datetime import timedelta
import hashlib
import os
import base64
from database import maazDB
import time




# Initialize Flask App
app = Flask(__name__)
app.secret_key = os.urandom(24)
app.permanent_session_lifetime = timedelta(minutes=30)

# Initialize maazDB instances
users_db = maazDB("users.dm")
messages_db = maazDB("messages.dm")

def generate_password_hash(password, method="pbkdf2:sha256", salt_length=16, iterations=5):
    """
    Hash a password using PBKDF2-SHA256.

    Args:
        password (str): The password to hash.
        method (str): The hashing method (default is 'pbkdf2:sha256').
        salt_length (int): The length of the salt (default is 16).
        iterations (int): The number of PBKDF2 iterations (default is 100,000).

    Returns:
        str: A hashed password in the format "method$salt$hash".
    """
    if method != "pbkdf2:sha256":
        raise ValueError("Unsupported hashing method")

    # Generate a random salt
    salt = os.urandom(salt_length)
    salt_hex = base64.b16encode(salt).decode('utf-8').lower()

    # Derive the hash using PBKDF2-HMAC-SHA256
    hash_bytes = hashlib.pbkdf2_hmac(
        'sha256', password.encode('utf-8'), salt, iterations
    )
    hash_hex = base64.b16encode(hash_bytes).decode('utf-8').lower()

    # Return the hashed password in the format "method$salt$hash"
    return f"{method}${salt_hex}${hash_hex}"

def check_password_hash(hashed_password, password):
    """
    Verify a password against a hashed password.
    """
    try:
        # Split the hashed password into its components
        method, salt_hex, hash_hex = hashed_password.split('$')

        # Ensure the method is supported
        if method != "pbkdf2:sha256":
            raise ValueError("Unsupported hashing method")

        # Decode the salt
        salt = base64.b16decode(salt_hex.upper())

        # Recompute the hash with the provided password and extracted salt
        hash_bytes = hashlib.pbkdf2_hmac(
            'sha256', password.encode('utf-8'), salt, 5
        )
        computed_hash_hex = base64.b16encode(hash_bytes).decode('utf-8').lower()

        # Compare the computed hash with the stored hash
        return computed_hash_hex == hash_hex
    except (ValueError, KeyError):
        return False

# Routes
@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    current_user = users_db.get(session['user_id'])
    if not current_user:
        flash('User not found!', 'danger')
        return redirect(url_for('login'))

    chat_with_user_id = request.args.get('chat_with', type=int)
    chat_with_user = users_db.get(chat_with_user_id) if chat_with_user_id else None

    '''messages = messages_db.query(
        lambda m: {m['sender_id'], m['receiver_id']} == {current_user['id'], chat_with_user_id}
    ) if chat_with_user else []'''

    return render_template(
        'home.html', 
        current_user=current_user, 
        chat_with_user=chat_with_user, 
        users=list(users_db.query(lambda u: True))  # List all users
        #messages=messages
    )


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password)

        # Check for existing username or email
        if users_db.query(lambda u: u['username'] == username):
            flash('Username already exists', 'danger')
        elif users_db.query(lambda u: u['email'] == email):
            flash('Email already exists', 'danger')
        else:
            new_user = {
                "id": len(users_db.data) + 1,
                "username": username,
                "email": email,
                "password": hashed_password
            }
            users_db.insert(new_user['id'], new_user)
            flash('Account created successfully!', 'success')
            return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = next((u for u in users_db.query(lambda u: u['email'] == email)), None)

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid credentials. Try again.', 'danger')

    return render_template('login.html')


@app.route('/send_message', methods=['POST'])
def send_message():
    if 'user_id' not in session:
        flash('User not logged in!', 'danger')
        return redirect(url_for('login'))

    content = request.form.get('content')
    receiver_id = request.form.get('receiver_id', type=int)

    if not content or not receiver_id:
        flash('Missing content or receiver ID!', 'danger')
        return redirect(url_for('home'))

    current_user = users_db.get(session['user_id'])
    if not current_user:
        flash('User not found!', 'danger')
        return redirect(url_for('login'))

    new_message = {
        'id': len(messages_db.data) + 1,
        'content': content,
        'sender_id': current_user['id'],
        'receiver_id': receiver_id,
        'timestamp': time.time()
    }

    try:
        messages_db.insert(new_message['id'], new_message)
        return {'status': 'success', 'message': new_message}, 200
    except Exception as e:
        flash(f'Error sending message: {str(e)}', 'danger')
        return redirect(url_for('home'))


@app.route('/fetch_messages', methods=['GET'])
def fetch_messages():
    if 'user_id' not in session:
        return {"error": "User not logged in"}, 403

    current_user_id = session['user_id']
    chat_with_user_id = request.args.get('chat_with', type=int)

    if not chat_with_user_id:
        return {"error": "Invalid or missing 'chat_with' parameter"}, 400

    messages = messages_db.query(
        lambda m: {m['sender_id'], m['receiver_id']} == {current_user_id, chat_with_user_id}
    )
    return {"messages": messages}, 200



@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.clear()  # Clears all session data
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))



if __name__ == '__main__':
    app.run(debug=True)

