import math
import os
import random
import shelve

import stripe
from flask import Flask, render_template, request, redirect, url_for, session, g, flash, jsonify
from flask_mail import Message, Mail
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

import Message as Msg
import Product
import Review
import User
from Forms import RegisterForm, ContactUsForm, ReviewForm, reportForm, FAQSearchForm, ForgetPasswordForm
from datetime import timedelta, datetime

from flask_mysqldb import MySQL
import MySQLdb.cursors
import bcrypt
from cryptography.fernet import Fernet


mail = Mail()

app = Flask(__name__)
app.secret_key = 'secret_key'
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 465
app.config["MAIL_USE_SSL"] = True
app.config["MAIL_USERNAME"] = 'securitproject2021@gmail.com'
app.config["MAIL_PASSWORD"] = 'securityproject123'
app.config['STRIPE PUBLIC KEY'] = 'pk_test_lfuZUTGObUfh7pa11TSt8CeA'
app.config['STRIPE_SECRET_KEY'] = 'sk_test_51Bn3MVDe4uhAIaEt75dOEI0bOr2ZI2RVfKSdSAxvvVnWYyjEsPsXm0BeU8WpKWTlNP82M7lKmd0GMAJL6umBRhh900DVMUFavT'
stripe.api_key = 'sk_test_51Bn3MVDe4uhAIaEt75dOEI0bOr2ZI2RVfKSdSAxvvVnWYyjEsPsXm0BeU8WpKWTlNP82M7lKmd0GMAJL6umBRhh900DVMUFavT'
UPLOAD_FOLDER = '/static/img/avatars'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

mail.init_app(app)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'Dominic23052001'
app.config['MYSQL_DB'] = 'SecurityProject'

# Intialize MySQL
mysql = MySQL(app)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.before_first_request
def before_first_request():
    email = 'admin@gmail.com'
    fname = 'Admin'
    lname = 'Admin'
    gender = 'M'
    password = 'admin123'
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    # Password Hashing
    # Create a random number (Salt)
    salt = bcrypt.gensalt(rounds=16)
    # A hashed value is created with hashpw() function, which takes the cleartext value and a salt as parameters.
    hash_password = bcrypt.hashpw(password.encode(), salt)

    cursor.execute('INSERT INTO accounts VALUES (%s, %s, %s, %s, %s, %s)',(1, email,hash_password,fname,lname,gender))
    mysql.connection.commit()

@app.before_request
def before_request():
    # db = shelve.open('register.db', 'r')
    # user_dict = db['Users']
    # g.user = None
    #
    # if 'user_id' in session:
    #     for key in user_dict:
    #         if key == session['user_id']:
    #             g.user = user_dict.get(key)
    #
    # db.close()
    g.account = None
    # Check if user is loggedin
    if 'user_id' in session:
        # We need all the account info for the user so we can display it on the profile page
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['user_id'],))
        g.account = cursor.fetchone()


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/login', methods=["GET", "POST"])
def login():
    error = ''
    if request.method == 'POST':
        #session.pop('user_id', None)
        session.clear()
        email = request.form['email']
        password = request.form['psw']
    #     # Check if account exists using MySQL
    #     cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    #     cursor.execute('SELECT * FROM accounts WHERE email = %s', (email,))
    #     # Fetch one record and return result
    #     g.account = cursor.fetchone()
    #     if g.account:
    #         # Extract the Salted-hash password from DB to local variable
    #         hashAndSalt = g.account['password']
    #         if bcrypt.checkpw(password.encode(), hashAndSalt.encode()):
    #             if g.account['email'] == 'admin@gmail.com':
    #                 session['user_id'] = g.account['id']
    #                 session['email'] = g.account['email']
    #                 return render_template('UserDashboard.html', account=g.account)
    #             # Create session data, we can access this data in other routes
    #             session['user_id'] = g.account['id']
    #             session['email'] = g.account['email']
    #             # Redirect to home page
    #             #return 'Logged in successfully!'
    #             #return redirect(url_for('home'))
    #
    #             return render_template('home.html', account=g.account)
    #
    #         else:
    #             # Account doesn’t exist or username/password incorrect
    #             error = '1 - Incorrect username/password!'
    #     else:
    #         # Account doesn’t exist or username/password incorrect
    #         error = '2 - Incorrect username/password!'
    # # Show the login form with message (if any)
    # return render_template('login.html',error=error)
    ################################ To prevent overwriting in database #################################
    users_dict = {}
    db = shelve.open('register.db', 'c')
    users_dict = db['Users']

    # User.User.count_id = db['Users_Count']
    users_list = []
    for key in users_dict:
        user = users_dict.get(key)
        users_list.append(user)

    db['Users_Count'] = len(users_list)  # Creates new key-value pair in Shelve db
    new_user_dict = {}

    for index, user in enumerate(users_list):
        user.set_user_id(index+1)
        new_user_dict[index+1] = user

    # Replacing db['Users'] database
    db['Users'] = new_user_dict
    db.close()
    ######################################################################################################
    error = None
    db = shelve.open('register.db', 'r')
    user_dict = db['Users']
    if request.method == 'POST':
        session.pop('user_id', None)
        email = request.form['email']
        password = request.form['psw']
        for key in user_dict:
            user = user_dict.get(key)
            if user.get_email() == email and check_password_hash(user.get_password(), password):
                if user.get_user_id() == 1:
                    session['user_id'] = user.get_user_id()

                    return redirect(url_for('user_dashboard'))
                session['user_id'] = user.get_user_id()

                return redirect(url_for('home'))

            else:
                error = 'Invalid Credentials. Please try again.'

    db.close()
    return render_template('login.html', error=error)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm(request.form)

    if request.method == 'POST' and form.validate():
        email = form.email.data
        fname = form.first_name.data
        lname = form.last_name.data
        gender = form.gender.data
        password = form.password.data
    #     cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    #     cursor.execute('SELECT * FROM accounts where email = %s', (email,))
    #     account = cursor.fetchone()
    #     #print(account)
    #     if account:
    #         email_error = 'Email has been registered!'
    #         return render_template('register.html', form=form,email_error=email_error)
    #     else:
    #         cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    #         # Password Hashing
    #         # Create a random number (Salt)
    #         salt = bcrypt.gensalt(rounds=16)
    #         # A hashed value is created with hashpw() function, which takes the cleartext value and a salt as parameters.
    #         hash_password = bcrypt.hashpw(password.encode(), salt)
    #
    #         cursor.execute('INSERT INTO accounts VALUES (NULL, %s, %s, %s, %s, %s)',(email,hash_password,fname,lname,gender))
    #         mysql.connection.commit()
    #         #error = 'You have successfully registered!'
    #         session['user_created'] = "You"
    #         #return render_template('login.html')
    #         return redirect(url_for('login'))
    # else:
    #     return render_template('register.html', form=form)
    elif request.method == "POST":
        # Form is empty... (no POST data)
        error = 'Please fill out the form!'
    return render_template('register.html', form=form, error=error, email_error=email_error, password_error=password_error)

        users_dict = {}
        db = shelve.open('register.db', 'c')

        try:
            users_dict = db['Users']
        except:
            print("Error in retrieving Users from register.db.")
        list_of_registered_emails = []
        for key in users_dict:
            user = users_dict.get(key)
            list_of_registered_emails.append(user.get_email())
        if form.email.data in list_of_registered_emails:
            error = 'Email has already been registered!'
        else:
            User.User.count_id = db['Users_Count']+1
            user = User.User(form.first_name.data, form.last_name.data, form.gender.data, form.email.data, generate_password_hash(form.password.data, method="sha256"))
            users_dict[user.get_user_id()] = user
            db['Users'] = users_dict
            db.close()
            session['user_created'] = "You"
            return redirect(url_for('login'))
        db.close()

        return render_template('register.html', form=form, error=error)
    else:
        return render_template('register.html', form=form)



@app.route('/forget_password', methods=["GET", "POST"])
def forget_password():
    global random_str, user_id, email, attempts_left
    error = None
    db = shelve.open('register.db', 'r')
    user_dict = db['Users']
    form = ForgetPasswordForm(request.form)

    if request.method == 'POST' and form.validate:
        if 'pin' in request.form:
            pin_input = request.form['pin']
            if attempts_left > 1:
                if pin_input == random_str:
                    session['user_id'] = user_id
                else:
                    attempts_left -= 1
                    error = f'Pin is incorrect. You have {attempts_left} attempts left.'
            else:
                error = 'You entered the wrong pin too many times.'
                return render_template('forget_password.html', form=form, error=error)

            if pin_input == random_str:
                return redirect(url_for('update_profile', id=user_id))
            else:
                return render_template('forget_password.html', error=error, form=form, email=email, pin=random_str, attempts_left=attempts_left)

        else:
            session.pop('user_id', None)
            email = request.form['email']

            for key in user_dict:
                user = user_dict.get(key)
                if user.get_email() == email:
                    user_id = user.get_user_id()
                    error = None
                    digits = [i for i in range(0, 10)]
                    random_str = ""
                    for i in range(6):
                        index = math.floor(random.random() * 10)
                        random_str += str(digits[index])
                    print(random_str)

                    confirmation = "We have sent you the reset password link in your email."
                    message = "We have sent you the reset password link in your email.\n\nThe pin is {}".format(random_str)
                    mail.send_message(
                        sender='abcrestaurant4@gmail.com',
                        recipients=[email],
                        subject="Reset Password For F&B Restaurant",
                        body=message
                    )
                    attempts_left = 4
                    return render_template('forget_password.html', error=error, form=form, message=confirmation, email=email, pin=random_str, user_id=user_id)
                else:
                    error = "Please enter a registered email account!"
    elif request.method == "GET":
        return render_template('forget_password.html', form=form)
    db.close()
    return render_template('forget_password.html', form=form, error=error)


@app.route('/dashboard')
def user_dashboard():
    users_dict = {}
    db = shelve.open('register.db', 'c')
    users_dict = db['Users']

    # User.User.count_id = db['Users_Count']
    users_list = []
    for key in users_dict:
        user = users_dict.get(key)
        users_list.append(user)

    db['Users_Count'] = len(users_list)  # Creates new key-value pair in Shelve db
    new_user_dict = {}

    for index, user in enumerate(users_list):
        user.set_user_id(index+1)
        new_user_dict[index+1] = user

    # Replacing db['Users'] database
    db['Users'] = new_user_dict
    db.close()

    if 'user_id' in session and session['user_id'] == 1:
        return render_template('UserDashboard.html', count=len(users_list), users_list=users_list)
    else:
        return 'You do not have authorized access to this webpage.'


@app.route('/updateUser/<int:id>/', methods=['GET', 'POST'])
def update_user(id):

    update_user_form = RegisterForm(request.form)
    if request.method == 'POST' and update_user_form.validate():
        users_dict = {}
        db = shelve.open('register.db', 'w')
        users_dict = db['Users']

        user = users_dict.get(id)

        user.set_first_name(update_user_form.first_name.data)
        user.set_last_name(update_user_form.last_name.data)
        user.set_gender(update_user_form.gender.data)
        user.set_password(generate_password_hash(update_user_form.password.data, method='sha256'))
        user.set_email(update_user_form.email.data)
        db['Users'] = users_dict

        db.close()

        session['user_updated'] = user.get_first_name() + ' ' + user.get_last_name()

        return redirect(url_for('user_dashboard'))
    else:
        users_dict = {}
        db = shelve.open('register.db', 'r')
        users_dict = db['Users']
        db.close()

        user = users_dict.get(id)
        update_user_form.first_name.data = user.get_first_name()
        update_user_form.last_name.data = user.get_last_name()
        update_user_form.gender.data = user.get_gender()
        update_user_form.email.data = user.get_email()
        update_user_form.password.data = user.get_password()
    if 'user_id' in session and session['user_id'] == 1:
        return render_template('updateUser.html', form=update_user_form)
    else:
        return 'You do not have authorized access to this webpage.'


@app.route('/updateProfile/<int:id>/', methods=['GET', 'POST'])
def update_profile(id):
    update_user_form = RegisterForm(request.form)

    if request.method == 'POST' and update_user_form.validate():
        users_dict = {}
        db = shelve.open('register.db', 'w')
        users_dict = db['Users']

        user = users_dict.get(id)
        avatar = request.files['avatar']
        if user.avatar is None:
            setattr(user, 'avatar', 'static/img/avatars/default.jpg')
        elif avatar.filename == '':
            setattr(user, 'avatar', user.avatar)
        elif avatar and allowed_file(avatar.filename):
            filename = secure_filename(avatar.filename)

            ver = 0
            while os.path.isfile('static/img/avatars/' + filename):  # if theres existing file
                ver += 1
                for filetype in ALLOWED_EXTENSIONS:
                    if filetype in filename.split('.'):
                        filename = avatar.filename.split('.')[0] + str(ver) + '.' + avatar.filename.split('.')[-1]

            filepath = '/static/img/avatars/' + filename

            avatar.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            setattr(user, 'avatar', filepath)
        elif not allowed_file(avatar.filename):
            fileTypeError = 'Invalid file type. (Only accepts .png, .jpg, .jpeg, and .gif files)'
            return render_template('updateProfile.html', id=id, form=update_user_form, fileTypeError=fileTypeError)
        for key in users_dict:
            user_obj = users_dict.get(key)
            email = user_obj.get_email()
            if update_user_form.email.data == user.get_email():
                break
            if update_user_form.email.data == email:
                emailError = "Email has already been registered!"
                return render_template('updateProfile.html', id=id, form=update_user_form, emailError=emailError)
        user.set_email(update_user_form.email.data)
        user.set_first_name(update_user_form.first_name.data)
        user.set_last_name(update_user_form.last_name.data)
        user.set_gender(update_user_form.gender.data)

        user.set_password(generate_password_hash(update_user_form.password.data, method='sha256'))

        db['Users'] = users_dict

        db.close()

        session['user_updated'] = user.get_first_name() + ' ' + user.get_last_name()
        session['profile_updated'] = 'Profile successfully updated!'
        return redirect(url_for('profile'))
    else:
        users_dict = {}
        db = shelve.open('register.db', 'r')
        users_dict = db['Users']
        db.close()

        user = users_dict.get(id)
        update_user_form.first_name.data = user.get_first_name()
        update_user_form.last_name.data = user.get_last_name()
        update_user_form.gender.data = user.get_gender()
        update_user_form.email.data = user.get_email()
        update_user_form.password.data = user.get_password()

        if 'user_id' in session and session['user_id'] == user.get_user_id():
            return render_template('updateProfile.html', form=update_user_form)
        else:
            return 'You do not have authorized access to this webpage.'

@app.route('/deleteUser/<int:id>', methods=['POST'])
def delete_user(id):
    users_dict = {}
    db = shelve.open('register.db', 'w')
    users_dict = db['Users']

    user = users_dict.pop(id)

    db['Users'] = users_dict

    db.close()

    session['user_deleted'] = user.get_first_name() + ' ' + user.get_last_name()

    return redirect(url_for('user_dashboard'))


@app.route('/FAQ', methods=["GET", "POST"])
def faq():
    form = FAQSearchForm(request.form)
    if request.method == "POST" and form.validate():
        if "sell" in form.search.data.lower():
            keyword = "sell"
        elif "not delivered" in form.search.data.lower() or "wrong order" in form.search.data.lower():
            keyword = ["not delivered", "wrong order"]
        elif "refund" in form.search.data.lower():
            keyword = "refund"
        elif "order" in form.search.data.lower():
            keyword = "order"
        elif "pay" in form.search.data.lower():
            keyword = "pay"
        elif "contact" in form.search.data.lower():
            keyword = "contact"
        elif "login" in form.search.data.lower() or "register" in form.search.data.lower():
            keyword = ["login", "register"]
        else:
            keyword = form.search.data.lower()
        return render_template('FAQ.html', form=form, kw=keyword)
    else:
        keyword = ""
        return render_template('FAQ.html', form=form, kw=keyword)


@app.route('/ContactUs', methods=['GET', 'POST'])
def contactus():
    form = ContactUsForm(request.form)
    if request.method == 'POST' and form.validate():
        messages_dict = {}
        db = shelve.open('messages.db', 'c')

        try:
            messages_dict = db['Messages']
        except:
            print("Error in retrieving Messages in messages.db")

        Msg.count_id = db['Messages_Count']+1

        message = Msg.Message(form.first_name.data, form.last_name.data, form.email.data, form.subject.data, form.enquiry.data)

        messages_dict[message.get_message_id()] = message
        db['Messages'] = messages_dict

        # Test codes
        messages_dict = db['Messages']
        message = messages_dict[message.get_message_id()]
        print(message.get_subject(), "was stored in messages.db successfully.")

        db.close()

        first_name = form.first_name.data
        last_name = form.last_name.data
        email = form.email.data
        subject = form.subject.data
        enquiry = form.enquiry.data

        msg = Message(subject, sender='abcrestaurant4@gmail.com', recipients=[email])
        msg.body = f'Hello, {first_name} {last_name}. \n\nHere was your message sent to us: {enquiry}\n\nThank you for your enquiry. We will get back to you soon.\n\nRegards, \nABC Restaurant'
        mail.send(msg)

        return render_template('ContactUs.html', success=True)
    else:
        flash('All fields are required.')
        return render_template('ContactUs.html', form=form)


@app.route('/retrieveMessages', methods=['GET', 'POST'])
def retrieve_messages():

    messages_dict = {}
    db = shelve.open('messages.db', 'c')
    messages_dict = db['Messages']

    messages_list = []
    for key in messages_dict:
        message = messages_dict.get(key)
        messages_list.append(message)

    db['Messages_Count'] = len(messages_list)
    new_messages_dict = {}

    for index, message in enumerate(messages_list):
        message.set_message_id(index+1)
        new_messages_dict[index+1] = message

    db['Messages'] = new_messages_dict
    db.close()

    if request.method == 'POST':
        recipient = request.form['recipient']
        email = request.form['email']
        subject = request.form['subject']
        reply = request.form['reply']
        msg = Message(subject, sender='abcrestaurant4@gmail.com', recipients=[email])
        msg.body = f'Hello, {recipient}.\n\n{reply}\n\nRegards,\nABC Restaurant'
        mail.send(msg)
        replysent = True
        return render_template('retrieveMessages.html', count=len(messages_list), messages_list=messages_list, replysent=replysent)
    else:
        if 'user_id' in session and session['user_id'] == 1:
            return render_template('retrieveMessages.html', count=len(messages_list), messages_list=messages_list)
        else:
            return 'You do not have authorized access to this webpage.'


@app.route('/deleteMessage/<int:id>', methods=["POST"])
def delete_message(id):
    messages_dict = {}
    db = shelve.open('messages.db', 'w')
    messages_dict = db['Messages']

    message = messages_dict.pop(id)

    db['Messages'] = messages_dict
    db.close()

    session['message_deleted'] = message.get_message_id()

    return redirect(url_for('retrieve_messages'))




@app.route('/profile')
def profile():
    return render_template('profile.html')

@app.route('/logout')
def logout():
    # remove the username from the session if it is there
    # session.pop('user_id', None)
    # session.pop('email', None)
    session.clear()
    return redirect(url_for('home'))


@app.route('/<product_id>/review', methods=['GET', 'POST'])
def review(product_id):
    users_dict = {}
    products = ['CknKb', 'CknRc', 'NsLmk', 'RtPrata', 'Water', 'TehTarik', 'IcedCola', 'anw']
    if product_id not in products:
        return '404 Page Not Found'
    else:
        form = ReviewForm(request.form)
        already_submitted = False
        db_name = 'Review-' + product_id
        db_count = db_name + '-Count'
        if request.method == 'POST' and form.validate():
            reviews_dict = {}
            db = shelve.open('reviews.db', 'c')

            try:
                reviews_dict = db[db_name]
            except:
                print("Error in retrieving Reviews from reviews.db.")

            Review.Review.count_id = db[db_count]+1

            review = Review.Review(form.rating.data, form.title.data, form.review.data, g.user)
            setattr(review, 'avatar', g.user.avatar)
            setattr(review, 'votes', 0)
            setattr(review, 'upvoters', [])
            setattr(review, 'downvoters', [])
            reviews_dict[review.get_review_id()] = review
            db[db_name] = reviews_dict
            db.close()
            return redirect(url_for('review_submitted'))
        elif request.method == 'GET':
            reviews_dict = {}
            db = shelve.open('reviews.db', 'c')
            userdb = shelve.open('register.db', 'w')
            try:
                reviews_dict = db[db_name]
            except:
                print("Error in retrieving Reviews from reviews.db")

            try:
                users_dict = userdb['Users']
            except:
                print("Error in retrieving Reviews from reviews.db")

            reviews_list = []
            for key in reviews_dict:
                rev = reviews_dict.get(key)
                reviews_list.append(rev)



            users_email_list = []
            for i in range(len(reviews_list)):
                review = reviews_list[i]
                for key in users_dict:
                    user = users_dict.get(key)
                    users_email_list.append(user.get_email())
                    if review.get_user_object().get_email() == user.get_email():
                        setattr(review.get_user_object(), 'avatar', user.avatar)
                        review.get_user_object().set_first_name(user.get_first_name())
                        review.get_user_object().set_last_name(user.get_last_name())
                if review.get_user_object().get_email() not in users_email_list:
                    review.get_user_object().set_first_name('[deleted]')
                    review.get_user_object().set_last_name('')
            if 'user_id' in session:

                for i in range(len(reviews_list)):
                    review = reviews_list[i]
                    if g.user.get_email() == review.get_user_object().get_email():
                        already_submitted = True
            reviews_list = sorted(reviews_list, key=lambda review: review.votes, reverse=True)

            db[db_count] = len(reviews_list)
            new_review_dict = {}

            for index, review in enumerate(reviews_list):
                review.set_review_id(index+1)
                new_review_dict[index+1] = review

            db[db_name] = new_review_dict
            db.close()

            template = 'products/' + product_id + '.html'
            return render_template(template, form=form, count=len(reviews_list), reviews_list=reviews_list, already_submitted=already_submitted)

@app.route('/review_submitted')
def review_submitted():
    return render_template('reviewSubmitted.html')

@app.route('/<product_id>/review/upvote/<int:review_id>/')
def upvote(product_id, review_id):
    if 'user_id' in session:
        reviews_dict = {}
        db_name = 'Review-' + product_id
        db = shelve.open('reviews.db', 'w')
        reviews_dict = db[db_name]

        review = reviews_dict.get(review_id)

        downvoters = review.downvoters
        upvoters = review.upvoters
        if g.user.get_email() in upvoters:
            votes = review.votes - 1
            setattr(review, 'votes', votes)
            upvoters.remove(g.user.get_email())
        else:
            votes = review.votes
            if g.user.get_email() in downvoters:
                votes = review.votes + 1
                downvoters.remove(g.user.get_email())
            votes = votes + 1
            setattr(review, 'votes', votes)
            upvoters.append(g.user.get_email())
            setattr(review, 'upvoters', upvoters)
        print(review.upvoters)
        db[db_name] = reviews_dict
        db.close()
        return redirect(url_for('review', product_id=product_id))
    else:
        return redirect(url_for('login'))

@app.route('/<product_id>/review/downvote/<int:review_id>/')
def downvote(product_id, review_id):
    if 'user_id' in session:
        reviews_dict = {}
        db_name = 'Review-' + product_id
        db = shelve.open('reviews.db', 'w')
        reviews_dict = db[db_name]

        review = reviews_dict.get(review_id)

        upvoters = review.upvoters
        downvoters = review.downvoters
        if g.user.get_email() in downvoters:
            votes = review.votes + 1
            setattr(review, 'votes', votes)
            downvoters.remove(g.user.get_email())
        else:
            votes = review.votes
            if g.user.get_email() in upvoters:
                votes = review.votes - 1
                upvoters.remove(g.user.get_email())
            votes = votes - 1
            setattr(review, 'votes', votes)
            downvoters.append(g.user.get_email())
            setattr(review, 'downvoters', downvoters)
        print(review.downvoters)
        db[db_name] = reviews_dict
        db.close()
        return redirect(url_for('review', product_id=product_id))
    else:
        return redirect(url_for('login'))

@app.route('/<product_id>/deleteReview/<int:id>', methods=["POST"])
def delete_review(product_id, id):
    reviews_dict = {}
    db_name = 'Review-' + product_id
    db = shelve.open('reviews.db', 'w')
    reviews_dict = db[db_name]
    print(db_name)
    print(reviews_dict[id].get_title())
    review = reviews_dict.pop(id)

    db[db_name] = reviews_dict
    db.close()

    return redirect(url_for('review', product_id=product_id))


@app.route('/<product_id>/updateReview/<int:id>/', methods=['GET', 'POST'])
def update_review(product_id, id):
    reviews_dict = {}
    db_name = 'Review-' + product_id
    db = shelve.open('reviews.db', 'w')
    reviews_dict = db[db_name]

    review = reviews_dict.get(id)

    review.set_rating(request.form['rating'])
    review.set_title(request.form['title'])
    review.set_review(request.form['review'])

    db[db_name] = reviews_dict
    db.close()

    return redirect(url_for('review', product_id=product_id))


@app.route('/ReportGeneration', methods=["GET", "POST"])
def report_generation():
    if 'user_id' in session and session['user_id'] == 1:
        option = ""
        users_list = []
        one_star_count = 0
        two_star_count = 0
        three_star_count = 0
        four_star_count = 0
        five_star_count = 0
        form = reportForm(request.form)

        users_dict = {}
        db = shelve.open('reviews.db', 'r')
        users_dict = db['Review-CknKb']
        db.close()

        for key in users_dict:
            user = users_dict.get(key)
            users_list.append(user)

        for i in range(len(users_list)):
            rating = users_list[i].get_rating()
            if int(rating) == 1:
                one_star_count += 1
            elif int(rating) == 2:
                two_star_count += 1
            elif int(rating) ==3:
                three_star_count += 1
            elif int(rating) == 4:
                four_star_count += 1
            elif int(rating) == 5:
                five_star_count += 1

        countlist=[one_star_count, two_star_count, three_star_count, four_star_count, five_star_count]

        if request.method == 'POST':
            if form.value.data =='Review Ratings':
                option ='Review Ratings'
            elif form.value.data == 'Customer Transaction History':
                option = 'Customer Transaction History'
            elif form.value.data == 'Total Amount':
                option = 'Total Amount'
            elif form.value.data == 'Payment Method':
                option = 'Payment Method'
        print(countlist)
        return render_template('ReportGeneration.html', form=form, option=option, count=len(users_list), countlist=countlist, users_list=users_list)
    else:
        return 'You do not have authorized access to this webpage.'


@app.route('/Products', methods=["GET", "POST"])
def add_to_cart():
    already_in_cart = False
    cart_dict = {}
    cart_list = []
    subtotal = 0
    if 'user_id' in session:
        user_id = session['user_id']
        if request.method == "POST":
            product_id = request.form.get('product_id')
            product_name = request.form.get('product_name')
            quantity = int(request.form.get('quantity'))
            price = round(float(request.form.get('price')), 2)

            db = shelve.open('cart.db', 'c')
            try:
                cart_dict = db['Cart']
            except:
                print('error')

            try:
                cart_list = cart_dict[user_id]
            except:
                pass

            for i in range(len(cart_list)):
                if product_id == cart_list[i].get_product_id():  # if cart already has the same product id
                    already_in_cart = True
                    current_quantity = cart_list[i].get_quantity()
                    new_quantity = current_quantity + quantity
                    cart_list[i].set_quantity(new_quantity)

                    new_price = price*cart_list[i].get_quantity()
                    cart_list[i].set_price(new_price)
                    break
            if not already_in_cart:
                product_obj = Product.Product(product_id, product_name, quantity, price)
                cart_list.append(product_obj)
                cart_dict[user_id] = cart_list

            db['Cart'] = cart_dict
            db.close()

        elif request.method == "GET":  # Counts how many things u have in cart upon loading page, displays it as Your Cart(1)
            db = shelve.open('cart.db', 'c')
            try:
                cart_dict = db['Cart']
            except:
                print('error')

            try:
                cart_list = cart_dict[user_id]
            except:
                pass

        for i in range(len(cart_list)):
            product_price = cart_list[i].get_price()
            subtotal += product_price

        return render_template('trialproductpage.html', cart_dict=cart_dict,
                               cart_list=cart_list, subtotal=round(subtotal, 2))
    else:
        return render_template('trialproductpage.html')


@app.route('/cart', methods=["GET", "POST"])
def cart():
    cart_dict = {}
    cart_list = []
    subtotal = 0
    if 'user_id' in session:
        user_id = session['user_id']
        db = shelve.open('cart.db', 'c')
        try:
            cart_dict = db['Cart']
        except:
            print('Error in retrieving cart_dict from cart.db')

        try:
            cart_list = cart_dict[user_id]
        except:
            pass

        for i in range(len(cart_list)):
            product_price = cart_list[i].get_price()
            subtotal += product_price
        # cart_dict = {user_id: cart_list}
        # cart_list = [<obj>, <obj>, <obj>]
        return render_template('cart.html', cart_dict=cart_dict, cart_list=cart_list, subtotal=round(subtotal, 2))
    else:
        return render_template('cart.html')


@app.route('/deleteProduct/<int:product_id>', methods=["POST"])
def delete_product(product_id):
    cart_list = []
    cart_dict = {}
    user_id = session['user_id']
    db = shelve.open('cart.db', 'w')
    try:
        cart_dict = db['Cart']
    except:
        print('Error in retrieving cart_dict from cart.db')

    try:
        cart_list = cart_dict[user_id]
    except:
        pass
    # cart_list = [<product object>, <product object>]
    # cart_dict = { 1: [<product object>, <product object>], 2: [<product object>, <product object]}
    cart_list.pop(product_id)
    cart_dict[user_id] = cart_list
    db['Cart'] = cart_dict

    db.close()

    return redirect(url_for('cart'))


@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    cart_dict = {}
    cart_list = []
    user_id = g.user.get_user_id()
    db = shelve.open('cart.db', 'c')
    try:
        cart_dict = db['Cart']
    except:
        print('error')


    try:
        cart_list = cart_dict[user_id]
    except:
        pass
    subtotal = 0
    for i in range(len(cart_list)):
        price = cart_list[i].get_price()
        subtotal += price
    subtotal = subtotal * 100

    session = stripe.checkout.Session.create(
        billing_address_collection='required',
        payment_method_types=['card'],
        line_items=[{
            'price_data': {
                'currency': 'sgd',
                'product_data': {
                    'name': 'Subtotal',
                },
                'unit_amount': int(subtotal),
            },
            'quantity': 1,
        }],
        mode='payment',
        success_url=url_for("success", _external=True),
        cancel_url=url_for("cart", _external=True),
    )



    db.close()

    return jsonify(id=session.id)


@app.route("/success")
def success():
    cart_dict = {}
    cart_list = []
    user_id = g.user.get_user_id()
    db = shelve.open('cart.db', 'c')
    try:
        cart_dict = db['Cart']
    except:
        print('error')


    try:
        cart_list = cart_dict[user_id]
    except:
        pass
    cart_list.clear()
    cart_dict[user_id] = cart_list
    db['Cart'] = cart_dict
    db.close()
    return render_template("Thanks.html")


if __name__ == '__main__':
    #app.run(debug=True, host='0.0.0.0')
    app.run(debug=True)

