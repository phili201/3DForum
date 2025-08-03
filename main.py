from flask import Flask, request, redirect, render_template, session, send_file, jsonify, url_for, send_from_directory
import json
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
import qrcode
import io
import base64
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask_mail import Mail, Message
import secrets
import time
import datetime
from flask_socketio import SocketIO, emit, join_room, send
import os
from werkzeug.utils import secure_filename
import random
from datetime import timedelta

reset_tokens = {}
active_login_tokens = {}
Max_failed_attempts = 3
lockout_duration = 15 * 60
Testmode = False


app = Flask(__name__)
app.secret_key = '3Dcommunication'
socketio = SocketIO(app)

app.config['MAIL_SERVER'] = 'smtp.ionos.de'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'prhode@e-mail.de'
app.config['MAIL_PASSWORD'] = 'Hase2012!'
app.config['MAIL_DEFAULT_SENDER'] = ('Philipp', 'prhode@e-mail.de')
mail = Mail(app)

Upload_folder = 'uploads'
Allowed_extensions = {'stl', 'obj', 'fbx', 'dea', 'zip'}
app.config['Upload_folder'] = Upload_folder

def get_maintrance_mode():
    with open('config.json', 'r') as file:
        config = json.load(file)
        return config.get('maintrance_mode', False)
def set_maintrance_mode(status:bool):
    with open('config.json', 'w') as file:
        json.dump({'maintrance_mode': status}, file)
def allowed_file(filename):
    return '.' in filename and \
            filename.rsplit('.', 1)[1].lower() in  Allowed_extensions

@app.template_filter('datetimeformat')
def datetimeformat(value, format='%d.%m.%Y %H:%M'):
    # value wird als Unix-Timestamp erwartet (float oder int)
    return datetime.datetime.fromtimestamp(value).strftime(format)


def send_email(to, subject, body):
    msg = Message(subject, recipients=[to])
    msg.body = body
    mail.send(msg)


def get_room_name(user1, user2):
    """Generiert einen eindeutigen Raumnamen für zwei Benutzer."""
    return '_'.join(sorted([user1, user2]))


@socketio.on('join')
def handle_join(data):
    username = session.get('username')
    other_user = data.get('other_user')
    if not username or not other_user:
        return
    room = get_room_name(username, other_user)
    join_room(room)
    emit('status', {'msg': f'{username} has entered the room.'}, room=room)


@socketio.on('send_message')
def handle_send_message(data):
    username = session.get('username')
    other_user = data.get('other_user')
    msg = data.get('msg')
    if not username or not other_user or not msg:
        return
    room = get_room_name(username, other_user)
    with open('private_messages.json', 'r') as file:
        pms = json.load(file)
        pms.append({
            'sender': username,
            'recipient': other_user,
            'message': msg,
            'timestamp': time.time()
        })
        with open('private_messages.json', 'w') as file:
            json.dump(pms, file)
        emit('receive_message', {'username': username, 'msg': msg}, room=room)


@app.route('/')
def home():
    maintrance = get_maintrance_mode()
    if maintrance and not session.get('freigeschaltet'):
       return render_template('home.html', maintrance=True)
    return render_template('home.html', maintrance=False)

@app.route('/wartungscode', methods=['POST', 'GET'])
def wartungscode():
    if request.method == 'POST':
        code = request.form['code']
        if code == 'Hase2012!':
           session['freigeschaltet'] = True
           return redirect('/') 
        else:
            return render_template('wartungscode.html', fehler='Falscher Code')
    else:
        return render_template('wartungscode.html')
app.permanent_session_lifetime = timedelta(days=7)
@app.route('/login', methods=['POST', 'GET'])
def login():
    with open('users.json', 'r') as file:
        users = json.load(file)
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in users:
            user = users[username]
            if user.get('lockout_time'):
                locked_until = user['lockout_time'] + lockout_duration
                if time.time() < locked_until:
                    remaining_time = int((locked_until - time.time()) / 60) + 1
                    return f'Account locked. Try again in {remaining_time} minutes.'
                else:
                    user['Failed_attempts'] = 0
                    user['lockout_time'] = None

            if check_password_hash(user['password'], password):
                if Testmode:
                    print("Testmode enabled, skipping 2FA")
                    session.permanent = True
                    session['username'] = username
                    return redirect('/dashboard')
                else:
                    totp = pyotp.TOTP(user['2fa_secret'])
                    if totp.verify(request.form.get('2fa_code', '')):
                        user['Failed_attempts'] = 0
                        user['lockout_time'] = None
                        with open('users.json', 'w') as file:
                            json.dump(users, file)
                        session.permanent = True
                        session['username'] = username
                        return redirect('/dashboard')
                    else:
                        user['Failed_attempts'] = user.get(
                            'Failed_attempts', 0) + 1
                        if user['Failed_attempts'] >= Max_failed_attempts:
                            user['lockout_time'] = time.time()
                            with open('users.json', 'w') as file:
                                json.dump(users, file)
                            return 'Account locked. Try again later.'
                        else:
                            versuche_verbleibend = Max_failed_attempts - user[
                                'Failed_attempts']
                            with open('users.json', 'w') as file:
                                json.dump(users, file)
                            return f"Invalid 2FA code. You have {versuche_verbleibend} attempts left."
            else:
                return 'Invalid username or password'
        else:
            return 'Invalid username or password'
    else:
        return render_template('login.html')


@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        with open('users.json', 'r') as file:
            users = json.load(file)
        if not username or not password:
            return 'Username and password are required'
        if username in users:
            return 'Username already exists'
        else:
            password_hash = generate_password_hash(password,
                                                   method='pbkdf2:sha256')
            secret = pyotp.random_base32()

            users[username] = {
                'password': password_hash,
                '2fa_secret': secret,
                'email': email,
                'Failed_attempts': 0,
                'lockout_time': None
            }

            with open('users.json', 'w') as file:
                json.dump(users, file)

            totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
                name=username, issuer_name="3D Community")

            img = qrcode.make(totp_uri)
            buffered = io.BytesIO()
            img.save(buffered, format="PNG")
            img_str = base64.b64encode(buffered.getvalue()).decode()

            send_email(
                to=email,
                subject="Welcome to 3D Community",
                body=
                f"Welcome to 3D Community, {username}! Your account has been created successfully."
            )

            return render_template('show_qr.html',
                                   qr_code=img_str,
                                   secret=secret)
    else:
        return render_template('register.html')


@app.route('/get/message/from/admin')
def get_message_from_admin():
    if 'username' not in session:
        return redirect('/login')
    with open('admin_messages.json', 'r') as file:
        messages = json.load(file)
    return render_template('admin_messages.html', messages=messages)


@app.route('/admin/messages/create', methods=['POST', 'GET'])
def admin_messages_create():
    if 'username' not in session or session['username'] != 'admin':
        return redirect('/login')
    if request.method == 'POST':
        title = request.form['title']
        message = request.form['message']
        date = request.form['date']
        with open('admin_messages.json', 'r') as file:
            messages = json.load(file)
            messages.append({'title': title, 'message': message, 'date': date})
            with open('admin_messages.json', 'w') as file:
                json.dump(messages, file)
                return redirect('/admin/messages')
    return render_template('admin_messages_create.html')


@app.route('/reset_password', methods=['POST', 'GET'])
def reset_password():
    if request.method == 'POST':
        email = request.form['email']
        with open('users.json', 'r') as file:
            users = json.load(file)
            for username, user_data in users.items():
                if user_data['email'] == email:
                    token = secrets.token_urlsafe(16)
                    reset_tokens[token] = username
                    link = url_for('reset_password_with_token',
                                   token=token,
                                   _external=True)
                    message = Message('Reset your password',
                                      recipients=[email])
                    message.body = f'Click the following link to reset your password: {link}'
                    mail.send(message)
                    return 'A reset link has been sent to your email.'
            return 'Email not found.'


@app.route('/qr_login')
def qr_login():
    token = secrets.token_urlsafe(16)
    expiry = time.time() + 240
    active_login_tokens[token] = {'status': 'pending', 'username': None}
    link = url_for('qr_login_confirm', token=token, _external=True)
    img = qrcode.make(link)
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    return render_template('qr_login.html', qr_code=img_str, token=token)


@app.route('/forgot/twofa/password', methods=['POST', 'GET'])
def forgot_twofa_password():
    if request.method == 'POST':
        email = request.form['email']
        with open('users.json', 'r') as file:
            users = json.load(file)
            for username, user_data in users.items():
                if user_data['email'] == email:
                    token = secrets.token_urlsafe(16)
                    reset_tokens[token] = username
                    link = url_for('reset_twofa_password',
                                   token=token,
                                   _external=True)
                    message = Message('Reset your 2FA password',
                                      recipients=[email])
                    message.body = f'Click the following link to reset your 2FA password: {link}'
                    mail.send(message)
                    return 'A reset link has been sent to your email.'
            return 'Email not found.'
    return render_template('forgot_twofa.html')


@app.route('/qr_login_status')
def qr_login_status():
    token = request.args.get('token')
    token_data = active_login_tokens.get(token)
    if token_data:
        if token_data.get('expires', 0) < time.time():
            del active_login_tokens[token]
            return jsonify({'status': 'expired'})
        return jsonify({'status': token_data['status']})
    return jsonify({'status': 'invalid'})


@app.route('/qr_login_confirm/<token>', methods=['POST', 'GET'])
def qr_login_confirm(token):
    if 'username' not in session:
        return "You are not logged in.", 403
    if token in active_login_tokens and active_login_tokens[token][
            'status'] == 'pending':
        active_login_tokens[token]['status'] = 'confirmed'
        active_login_tokens[token]['username'] = session['username']
        return 'Login confirmed.'
    return 'Invalid or expired token.', 400


@app.route('/reset/twofa/password/<token>', methods=['POST', 'GET'])
def reset_twofa_password(token):
    username = reset_tokens.get(token)
    if not username:
        return 'Invalid or expired token.'
    if request.method == 'POST':
        new_secret = pyotp.random_base32()
        with open('users.json', 'r') as file:
            users = json.load(file)
        users[username]['2fa_secret'] = new_secret
        with open('users.json', 'w') as file:
            json.dump(users, file)
        reset_tokens.pop(token)
        return 'Your 2FA password has been reset.'
    users[username]['2fa_secret'] = new_secret
    with open('users.json', 'w') as file:
        json.dump(users, file)
    otp_uri = pyotp.totp.TOTP(new_secret).provisioning_uri(
        name=username, issuer_name="3D Community")
    qr_img = qrcode.make(otp_uri)
    buffered = io.BytesIO()
    qr_img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    return render_template('reset_twofa.html',
                           qr_code=img_str,
                           username=username)


@app.route('/admin/switch_2fa/<username>', methods=['POST'])
def switch_2fa(username):
    if session.get('admin') != True:
        return redirect('/admin_login')
    with open('users.json', 'r') as file:
        users = json.load(file)
    if username in users:
        new_secret = pyotp.random_base32()
        users[username]['2fa_secret'] = new_secret
        with open('users.json', 'w') as file:
            json.dump(users, file, indent=4)
        return "The 2FA code for the user{username} has been reset."
    else:
        return "User not found."


@app.route('/admin/show_qr/<username>', methods=['GET'])
def show_qr(username):
    with open('users.json', 'r') as file:
        users = json.load(file)
        if username not in users:
            return 'User not found'
        secret = users[username]['2fa_secret']
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=username, issuer_name="3D Community")
        img = qrcode.make(totp_uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)
        return send_file(buf, mimetype='image/png')


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/')


@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('forum.html')
    else:
        return redirect('/login')


@app.route('/profile')
def profile():
    if 'username' not in session:
        return redirect('/login')
    username = session['username']
    with open('users.json', 'r') as user_data:
        user_data = json.load(user_data)
        user_data = user_data.get(username)
    return render_template('profile.html',
                           username=username,
                           user_data=user_data)


@app.route('/change_password', methods=['POST', 'GET'])
def change_password():
    if 'username' not in session:
        return redirect('/login')
    username = session['username']
    if request.method == 'POST':
        with open('users.json', 'r') as file:
            users = json.load(file)
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        if check_password_hash(users[username]['password'], old_password):
            users[username]['password'] = generate_password_hash(
                new_password, method='pbkdf2:sha256')
            with open('users.json', 'w') as file:
                json.dump(users, file)
            return 'Password changed successfully'
        else:
            return 'Invalid old password'
    return render_template('change_password.html')


@app.route('/reset_2fa', methods=['POST', 'GET'])
def reset_2fa():
    if 'username' not in session:
        return redirect('/login')
    username = session['username']
    with open('users.json', 'r') as file:
        users = json.load(file)
    new_secret = pyotp.random_base32()
    users[username]['2fa_secret'] = new_secret
    with open('users.json', 'w') as file:
        json.dump(users, file)
    totp_uri = pyotp.totp.TOTP(new_secret).provisioning_uri(
        name=username, issuer_name="3D Community")
    img = qrcode.make(totp_uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype='image/png')



@app.route('/delete_account', methods=['POST', 'GET'])
def delete_account():
    if 'username' not in session:
        return redirect('/login')
    username = session['username']
    if request.method == 'POST':
        with open('users.json', 'r') as file:
            users = json.load(file)
        if username in users:
            password = request.form.get('password')
            twofa_code = request.form.get('2fa_code')
            if not check_password_hash(users[username]['password'], password):
                return "Invalid password", 403
            totp = pyotp.TOTP(users[username]['2fa_secret'])
            if not totp.verify(twofa_code):
                return "Invalid 2FA code", 403
            del users[username]
            with open('users.json', 'w') as file:
                json.dump(users, file)
            session.pop('username', None)
    return render_template('confirm_delete.html')


@app.route('/forum')
def forum():
    with open('messages.json', 'r') as file:
        messages = json.load(file)
        return render_template('forum.html', messages=messages)


@app.route('/post_message', methods=['POST'])
def post_message():
    username = session.get('username')
    if not username:
        return redirect('/login')
    text = request.form['message']
    file = request.files.get('file')
    filename = None
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['Upload_folder'], filename)
        file.save(filepath)
    with open('messages.json', 'r') as file:
        messages = json.load(file)
    messages.append({'username': username, 'text': text, 'file': filename})
    with open('messages.json', 'w') as file:
        json.dump(messages, file)
        return redirect('/forum')

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['Upload_folder'], filename)
    

@app.route('/delete_message/<int:index>', methods=['POST'])
def delete_message(index):
    if 'username' not in session:
        return redirect('/login')

    username = session['username']

    with open('messages.json', 'r') as file:
        messages = json.load(file)

    if index < len(messages):

        if messages[index]['username'] == username or username == 'admin':
            del messages[index]
            with open('messages.json', 'w') as file:
                json.dump(messages, file)

    return redirect('/forum')


@app.route('/api/forum_messages')
def api_forum_messages():

    with open('messages.json', 'r') as file:
        messages = json.load(file)
    return jsonify(messages)


@app.route('/post_reply/<int:index>', methods=['POST'])
def post_reply(index):
    if 'username' not in session:
        return redirect('/login')
    username = session['username']
    text = request.form['reply']

    with open('messages.json', 'r') as file:
        messages = json.load(file)

    if index < len(messages):
        if 'replies' not in messages[index]:
            messages[index]['replies'] = []
        messages[index]['replies'].append({'username': username, 'text': text})

        with open('messages.json', 'w') as file:
            json.dump(messages, file)

        with open('users.json', 'r') as file:
            users = json.load(file)
        original_author = messages[index]['username']
        if original_author in users:
            email = users[original_author].get('email')
            if email and email != users[username].get('email'):
                subject = "New reply to your message on 3D Community"
                body = (
                    f"Hi {original_author},\n\n"
                    f"You have a new reply to your message on 3D Community.\n\n"
                    f"Message: {messages[index]['text']}\n\n"
                    f"Reply: {text}\n\n"
                    "Best regards,\n3D Community Team")
                try:
                    send_email(to=email, subject=subject, body=body)
                except Exception as e:
                    print(f"Failed to send email: {e}")

    return redirect('/forum')


@app.route('/pm/send', methods=['POST', 'GET'])
def pm_send():
    if 'username' not in session:
        return redirect('/login')
    if request.method == 'POST':
        recipient = request.form['to']
        message = request.form['message']
        sender = session['username']

        if recipient == sender:
            return "You can't send a message to yourself"
        with open('users.json', 'r') as file:
            users = json.load(file)
        if recipient not in users:
            return "Recipient not found"
        with open('private_messages.json', 'r') as file:
            pms = json.load(file)

        pms.append({
            'sender': sender,
            'recipient': recipient,
            'message': message,
            'timestamp': time.time()
        })
        with open('private_messages.json', 'w') as file:
            json.dump(pms, file)

        email = users[recipient].get('email')
        if email:
            subject = "New private message on 3D Community"
            body = f"Hi {recipient},\n\nYou have a new private message from {sender}:\n\n{message}\n\nBest regards,\n3D Community Team"
            try:
                send_email(to=email, subject=subject, body=body)
            except Exception as e:
                print(f"Failed to send email: {e}")
        return redirect('/pm/inbox')
    return render_template('send_pm.html')


@app.route('/pm/inbox')
def pm_inbox():
    if 'username' not in session:
        return redirect('/login')
    username = session['username']
    with open('private_messages.json', 'r') as file:
        pms = json.load(file)
    user_pms = [pm for pm in pms if pm['recipient'] == username]
    user_pms.sort(key=lambda pm: pm['timestamp'], reverse=True)
    contacts = list({pm['sender'] for pm in user_pms})
    return render_template('inbox.html', pms=user_pms, contacts=contacts)


@app.route('/pm/chat/<other_user>')
def pm_chat(other_user):
    if 'username' not in session:
        return redirect('/login')
    username = session['username']

    with open('private_messages.json', 'r') as file:
        pms = json.load(file)
    chat_pms = [
        pm for pm in pms
        if (pm['sender'] == username and pm['recipient'] == other_user) or (
            pm['sender'] == other_user and pm['recipient'] == username)
    ]
    chat_pms.sort(key=lambda pm: pm['timestamp'])

    return render_template('chat.html',
                           chat_pms=chat_pms,
                           other_user=other_user)


@app.route('/pm/delete', methods=['POST'])
def delete_pm():
    if 'username' not in session:
        return redirect('/login')
    username = session['username']
    timestamp = float(request.form['timestamp'])

    with open('private_messages.json', 'r') as file:
        messages = json.load(file)

    # Lösche Nachricht, wenn sie an den Nutzer gerichtet ist
    messages = [
        msg for msg in messages
        if not (msg['timestamp'] == timestamp and msg['recipient'] == username)
    ]

    with open('private_messages.json', 'w') as file:
        json.dump(messages, file, indent=2)

    return redirect('/pm/inbox')


@app.route("/pm/inbox/data")
def inbox_data():
    if 'username' not in session:
        return jsonify([])
    username = session['username']
    with open('private_messages.json', 'r') as f:
        all_pms = json.load(f)
    pms = all_pms.get(username, [])
    return jsonify(pms)


@app.route('/admin_login', methods=['POST', 'GET'])
def admin_login():
    if request.method == 'POST':
        with open('admin.json', 'r') as file:
            admin = json.load(file)
            username = request.form['username']
            password = request.form['password']
            if username in admin and admin[username]['password'] == password:
                totp = pyotp.TOTP(admin[username]['2fa_secret'])
                if totp.verify(request.form['2fa_code']):
                    session['admin'] = True
                    session['admin_username'] = username
                    print("Session data:", session)
                    return redirect('/admin_dashboard')
                else:
                    return 'Invalid 2FA code'
            else:
                return 'Invalid username or password'
    else:
        return render_template('admin_login.html')


@app.route('/admin_dashboard', methods=['POST', 'GET'])
def admin_dashboard():
    if session.get('admin') == True:
        print("Session data:", session)
        username = session.get('admin_username', 'admin')
        if request.method == 'POST':
            toggle = request.form.get('toggle')
            if toggle == 'on':
                set_maintrance_mode(True)
            elif toggle == 'off':
                set_maintrance_mode(False)
                session.pop('freigeschaltet', None)  
        maintrance_mode = get_maintrance_mode()
        return render_template('admin_dashboard.html', username=username, maintrance_mode=maintrance_mode)
    else:
        print("Nothing in session")
        return redirect('/admin_login')


@app.route('/admin/users')
def admin_users():
    if session.get('admin') == True:
        with open('admin.json', 'r') as admin_file:
            admin = json.load(admin_file)
        with open('users.json', 'r') as file:
            users = json.load(file)
        return render_template('admin_users.html', users=users, admin=admin)
    else:
        return redirect('/admin_login')


@app.route('/admin/delete_user/<username>', methods=['GET', 'POST'])
def admin_delete_user(username):
    if session.get('admin') != True:
        return redirect('/admin_login')

    with open('users.json', 'r') as file:
        users = json.load(file)

    if username not in users:
        return 'User not found'

    if username == 'admin':
        if request.method == 'POST':
            entered_password = request.form.get('admin_password', '')
            with open('admin.json', 'r') as admin_file:
                admin = json.load(admin_file)
            if admin.get('admin') != entered_password:
                return 'Invalid admin password'
            del users[username]
            del admin['admin']
            with open('users.json', 'w') as file:
                json.dump(users, file)
            with open('admin.json', 'w') as admin_file:
                json.dump(admin, admin_file)
            session.pop('admin', None)
            return redirect('/admin_login')

        return render_template('admin_delete_admin.html')
    del users[username]
    with open('users.json', 'w') as file:
        json.dump(users, file)
    return redirect('/admin/users')


@app.route('/admin_logout')
def admin_logout():
    session.pop('admin', None)
    return redirect('/admin_login')


@app.route('/admin/username/switch/<username>', methods=['POST'])
def switch_username(username):
    if session.get('admin') != True:
        return redirect('/admin_login')
    with open('users.json', 'r') as file:
        users = json.load(file)
        if username not in users:
            return 'User not found'
        if request.method == 'POST':
            new_username = request.form['new_username']
            if new_username in users:
                return 'Username already exists'
            users[new_username] = users.pop(username)
            with open('users.json', 'w') as file:
                json.dump(users, file)
            return f"Username changed from{username} to {new_username}"
    return redirect('/admin_dashboard')


if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
