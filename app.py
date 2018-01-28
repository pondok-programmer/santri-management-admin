import datetime
from flask import Flask, render_template, request, session, redirect, url_for, flash
from peewee import *
from hashlib import md5


app = Flask(__name__)
app.secret_key = 'secret_13348394032sloro'


#  =====================================================
# # Database ============================================
# # ====================================================

DATABASE = 'santri.db'
database = SqliteDatabase(DATABASE)

class BaseModel(Model):
	class Meta:
		database = database

class AdminLogin(BaseModel):
	username = CharField(unique=True)
	password = CharField()
	email = CharField(unique=True)
	join_at = DateTimeField(default=datetime.datetime.now())

class Grup(BaseModel):
	id = IntegerField(primary_key=True)
	name = CharField(max_length=20)
	description = TextField()

class User(BaseModel):
	id = IntegerField(primary_key=True)
	username = CharField(max_length=20)
	born_date = DateTimeField(default=datetime.datetime.now())
	grup = ForeignKeyField(Grup, backref='users')


class Relationship(BaseModel):
	adminlogin = ForeignKeyField(AdminLogin, backref='relationships')
	user = ForeignKeyField(User, backref='relationships')
	grup = ForeignKeyField(Grup, backref='relationships')

	class Meta:
		indexes = (
			(('adminlogin', 'user', 'grup'), True),
		)

@app.before_request
def before_request():
	database.connect()

@app.after_request
def after_request(response):
	database.close()
	return response


def create_tables():
	with database:
		database.create_tables([AdminLogin, Grup, Relationship, User])

#  =====================================================
# # Routing ============================================
# # ====================================================


@app.route('/')
def homepage():
	return render_template('index.html')

def auth_user(user):
	session['logged_in'] = True
	session['user_id'] = user.id
	session['username'] = user.username
	flash('You have successfully logged in as ' + session['username'])

def get_current_user():
	if session.get('logged_in'):
		return AdminLogin.get(AdminLogin.id == session['user_id'])



@app.route('/register', methods=['GET', 'POST'])
def register():
	if request.method == 'POST' and request.form['username']:
		try:
			with database.atomic():
				adminlogin = AdminLogin.create(
					username = request.form['username'],
					password = md5(request.form['password'].encode('utf-8')).hexdigest(),
					email = request.form['email']
				)  

			auth_user(user)
			return redirect(url_for('homepage'))
		
		except IntegrityError:
			flash('User already registered')

		else:
			auth_user(user)
			return redirect(url_for('homepage'))


	return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
	if request.method == 'POST' and request.form['username']:
		try:
			hashed_pass = md5(request.form['password'].encode('utf-8')).hexdigest()
			user = AdminLogin.get(
				(AdminLogin.username == request.form['username']) &
				(AdminLogin.password == hashed_pass)
			)
		except AdminLogin.DoesNotExist:
			flash('Incorrect User or Password')

		else:
			auth_user(user)
			return redirect(url_for('homepage'))
	
	return render_template('login.html')

if __name__ == '__main__':
	app.run(debug=True)