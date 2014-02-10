import os
import re
import webapp2
import jinja2
import time
import hashlib
import hmac
import random
import logging
import random
from string import letters
from google.appengine.ext import db
from google.appengine.api import memcache

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

secret = 'yuma'
front_pic = ['front1.jpg','front2.jpg','front3.jpg','front4.jpg']

def render_str(template, **params):
	t = jinja_env.get_template(template)
	return t.render(params)



def make_secure_val(val):
	return '%s|%s' % (val, hmac.new(secret,val).hexdigest())

def check_secure_val(secure_val):
	val = secure_val.split('|')[0]
	if secure_val == make_secure_val(val):
		return val

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		params['user'] = self.user
		return render_str(template, **params)
	
	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	#setting the cookie
	def set_secure_cookie(self, name, val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header(
			'Set-Cookie',
			'%s=%s; Path=/' % (name, cookie_val))
	
	def read_secure_cookie(self,name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

	def login(self, user):
		self.set_secure_cookie('user_id', str(user.key().id()))

	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie('user_id')
		self.user = uid and User.by_id(int(uid))



####### User stuff
def make_salt(length=5):
	return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt=None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
	salt = h.split(',')[0]
	return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
	return db.Key.from_path('users', group)

######### Database Objects

class User(db.Model):
	name = db.StringProperty(required=True)
	pw_hash = db.StringProperty(required = True)
	email = db.StringProperty()

	@classmethod
	def by_id(cls, uid):
		return User.get_by_id(uid, parent = users_key())

	@classmethod
	def by_name(cls, name):
		u = User.all().filter('name =', name).get()
		return u

	@classmethod
	def register(cls, name, pw, email = None):
		pw_hash = make_pw_hash(name, pw)
		return cls(parent = users_key(),
					name = name,
					pw_hash = pw_hash,
					email = email)
	
	@classmethod
	def login(cls, name, pw):
		u = cls.by_name(name)
		if u and valid_pw(name, pw, u.pw_hash):
			return u

class Post(db.Model):
	title = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)
	
	def render(self):
		self._render_text = self.content.replace('\n', '<br>')
		return render_str("post.html", p = self)

def get_posts(update=False):
	key = 'top'
	posts = memcache.get(key)

	if posts is None or update:
		logging.error("DB QUERY")
		posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC limit 10")
		memcache.set(key, posts)
	return posts

############ Pages
class MainPage(Handler):
	
	def render_front(self, title = "", content = "", error = ""):
		posts = get_posts()
		self.render("front.html", posts=posts)		#pass into template 
	
	def get(self):
		self.render_front()

	def post(self):
		time.sleep(2)
		self.redirect("/home")

class Home(Handler):
	
	def render_front(self):
		pic = random.choice(front_pic)
		print pic
		self.render("home.html", pic=pic)
	
	def get(self):
		self.render_front()


class About(Handler):
	def render_front(self):
		self.render("about.html")
	def get(self):
		self.render_front()

class Projects(Handler):
	def render_front(self):
		self.render("projects.html")
	def get(self):
		self.render_front()

class ProjectHp(Handler):
	def get(self):
		self.render("project-hp.html")


class ProjectEm(Handler):
	def get(self):
		self.render("project-em.html")

class ProjectAer(Handler):
	def get(self):
		self.render("project-aer.html")

class ProjectUtek(Handler):
	def get(self):
		self.render("project-utek.html")

class ProjectUtra(Handler):
	def get(self):
		self.render("project-utra.html")

class ProjectPraxis(Handler):
	def get(self):
		self.render("project-praxis.html")


class BlogEntry(Handler):
	def render_front(self, title = "", content = "", error = ""):
		self.render("entry.html", title=title, content=content, error=error)		#pass into template 

	def get(self):
		
		if (self.user) and (self.user.name == 'yuma'):
			self.render_front()
		else:
			self.redirect('/login')
	
	def post(self):
		title = self.request.get("title")
		content = self.request.get("content")
		
		if title and content:
			p = Post(title = title, content = content)
			p.put() 	#stores a into data base
			get_posts(True)
			time.sleep(0.5)	
			self.redirect("/blog")
		else:
			error = "we need both title and content!"
			self.render_front(title, content, error)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(Handler):
	def get(self):
		self.render("signup-form.html")
	def post(self):
		have_error = False
		self.username = self.request.get('username')
		self.password = self.request.get('password')
		self.verify = self.request.get('verify')
		self.email = self.request.get('email')
		params = dict(username = self.username, email = self.email)
		if not valid_username(self.username):
			params['error_username'] = "That's not a valid username."
			have_error = True
		
		if not valid_password(self.password):
			params['error_password'] = "That wasn't a valid password."
			have_error = True
		elif self.password != self.verify:
			params['error_verify'] = "Your passwords didn't match."
			have_error = True

		if not valid_email(self.email):
			params['error_email'] = "That's not a valid email."
			have_error = True

		if have_error:
			self.render('signup-form.html', **params)
		else:
			self.done()
	def done(self, *a, **kw):
		raise NotImplementedError

class Register(Signup):
    def done(self):
		#make sure the user doesn't already exist
		u = User.by_name(self.username)

		if u:
			msg = 'That user already exists.'
			self.render('signup-form.html', error_username = msg)
		else:
			u = User.register(self.username, self.password, self.email)
			u.put()
			self.login(u)
			self.redirect('/entry')
	
class Login(Handler):
	def get(self):
		self.render('login-form.html')
	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')
		u = User.login(username, password)
		if u:
		    self.login(u)
		    self.redirect('/entry')
		else:
		    msg = 'Invalid login'
		    self.render('login-form.html', error = msg)

class Logout(Handler):
	def get(self):
		self.logout()
		self.redirect('/blog')

application = webapp2.WSGIApplication([
	('/blog', MainPage), 
	('/entry', BlogEntry), 
	('/', Home),
	('/about', About),
	('/projects', Projects),
	('/project_hp', ProjectHp),
	('/project_em', ProjectEm),	
	('/project_aer', ProjectAer),	
	('/project_utek', ProjectUtek),	
	('/project_utra', ProjectUtra),	
	('/project_praxis', ProjectPraxis),	
	('/login', Login),	                    
	('/logout', Logout),
	],
	debug=True)	
