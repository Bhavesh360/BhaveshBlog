#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import os
import webapp2
import jinja2 
import re
from string import letters
import hmac
import logging
import random
import hashlib
import json
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True) 

secret = 'Bhaveshssecrethash'
#validating username, password, verify password and email
username_re = re.compile(r"^[a-zA-Z0-9_-]{3,20}$") #should contain characters from a-z,A-Z and 0-9 and should be 3-20 characters long.
def valid_username(username):
    return username and username_re.match(username)

password_re = re.compile(r"^.{3,20}$") #could contain all characters and should be 3-20 chars long.
def valid_password(password):
    return password and password_re.match(password)

email_re = re.compile(r"^[\S]+@[\S]+.[\S]+$")
def valid_email(email):
    return not email or email_re.match(email)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        t = jinja_env.get_template(template)
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def render_json(self, d):
        json_txt = json.dumps(d)
        self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
        self.write(json_txt)

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
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

        if self.request.url.endswith('.json'):
            self.format = 'json'
        else:
            self.format = 'html'


class MainHandler(Handler):
    def get(self):
        self.write('Hello Bhavesh!')

##User informatioon handling:
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h= hashlib.sha256(name + pw + salt).hexdigest()
    return '%s, %s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users',group)

class User(db.Model):
    name = db.StringProperty(required = True)
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
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

#######lets make a blog ameeeego. 


def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name) # I am not sure what this is for yet but its like I have set up a stage for multiple blogs by having a parent.

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p =self)

    def as_dict(self):
        time_fmt = '%c'
        d = {'subject': self.subject,
             'content': self.content,
             'created': self.created.strftime(time_fmt),
             'last_modified': self.last_modified.strftime(time_fmt)}
        return d

class BlogPage(Handler):
    def get(self):
        # posts = Post.all().order('-created') #googles procedural language instead of GQL that we've been till now. 
        posts = db.GqlQuery("select * from Post order by created desc limit 10")
        if self.format == 'html':
            self.render("front.html", posts = posts)
        else:
            return self.render_json([p.as_dict() for p in posts])

class PostPage(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent = blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return
        if self.format == 'html':
            self.render("permalink.html", post = post)
        else:
            self.render_json(post.as_dict())

class NewPost(Handler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p= Post(parent  = blog_key(), subject = subject, content = content)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id())) # when you do p.put you store this data in the database. and google datastore gives it an id. 
                                                            #This id can be fetched by p.key().id() which is an integer representation of the id. 
        else:
            error = "enter subject and content both, please!"
            self.render("newpost.html", subject = subject, content = content, error = error)

class SignupHandler(Handler):
    def get(self):
        self.render('signup-form.html')

    def post(self):
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        have_error= False
        params = dict(username= self.username, email = self.email)
        if not valid_username(self.username):
            params['error_username'] = 'You have entered an invalid username'
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = 'You have entered an invalid password'
            have_error = True
        elif self.verify!=self.password:
            params['error_verify'] = 'Your passwords do not match'
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = 'You have entered an invalid email address'
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            self.done()
            # self.redirect('/unit2/welcome?username=' + username)


    def done(self, *a, **kw):
        raise NotImplementedError

class Unit2Signup(SignupHandler):
    def done(self):
        self.redirect('/unit2/welcome?username=' + self.username)

class Register(SignupHandler):
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
            #self.set_secure_cookie('user_id', str(u.key().id()))
            self.redirect('/unit3/welcome')
class Login(Handler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password) #this login is from the Userclass.
        if u:
            self.login(u)
            self.redirect('/unit3/welcome')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/signup')

class Unit3Welcome(Handler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            #self.render('newpost.html')
            self.redirect('/signup')

class WelcomeHandler(Handler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username = username)
        else:
            self.redirect('/unit2/signup')


app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/unit2/signup', Unit2Signup),
    ('/blog/?(?:.json)?', BlogPage),
    ('/blog/([0-9]+)(?:.json)?', PostPage),
    ('/blog/newpost', NewPost),
    ('/signup', Register),
    ('/login', Login),
    ('/logout', Logout),
    ('/unit2/welcome', WelcomeHandler),
    ('/unit3/welcome', Unit3Welcome),
], debug=True)
