#!/usr/bin/env python
import os
import re
import random
import webapp2
import hashlib
import hmac
from string import letters

import jinja2

from google.appengine.ext import ndb

# Jinja Configuration
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


# Global Variables

secret = "as;digjh34968qt[asireg"

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")


# Global Functions

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


def get_item(item_type, item_id):
    key = ndb.Key(item_type, int(item_id))
    item = key.get()
    return item


def get_comments(post_id):
    comments = Comment.query(Comment.post_id == post_id)
    comments = comments.order(Comment.comment_date)
    return comments


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


def valid_username(username):
    return USER_RE.match(username)


def valid_password(password):
    return PASS_RE.match(password)


def valid_email(email):
    return EMAIL_RE.match(email)


def user_required(func):
    """ makes sure that the user is logged in """
    def check_user(self, *args, **kwargs):
        if self.user:
            return func(self, *args, **kwargs)
        else:
            self.redirect("/login")
    return check_user



# Data Models
class Post(ndb.Model):
    """
    Creates an instance of the class that allows creation of new
    posts that may be stored as entities
    """
    post_title = ndb.StringProperty(required=True)
    post_text = ndb.TextProperty(required=True)
    post_created = ndb.DateTimeProperty(auto_now_add=True)
    last_modified = ndb.DateTimeProperty(auto_now=True)
    created_by = ndb.StringProperty(required=True)
    likes = ndb.StringProperty(repeated=True)

    def render_post(self):
        self._render_text = self.post_text.replace('\n', '<br>')
        return render_str("post.html", p=self)


class User(ndb.Model):
    """
    Creates an instance of the class that allows creation of new users
    that may be stored as entities
    """
    name = ndb.StringProperty(required=True)
    pw_hash = ndb.StringProperty(required=True)
    email = ndb.StringProperty()

    @classmethod
    def by_id(cls, uid):
        """ Retrieves a user by id """
        return User.get_by_id(uid)

    @classmethod
    def by_name(cls, name):
        """ Retrieves a user by username """
        u = User.query(User.name == name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        """ Creates a new user """
        pw_hash = make_pw_hash(name, pw)
        return User(name=name, pw_hash=pw_hash, email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


class Comment(ndb.Model):
    """
    Creates an instance of the class that allows creation of new
    comments that may be stored as entities
    """
    username = ndb.StringProperty(required=True)
    comment_title = ndb.StringProperty(required=True)
    comment_text = ndb.TextProperty(required=True)
    post_id = ndb.StringProperty(required=True)
    comment_date = ndb.DateTimeProperty(auto_now_add=True)
    likes = ndb.StringProperty(repeated=True)

    def render_comments(self):
        """
        Replaces carriage returns in comments so that they can be rendered
        correctly
        """
        self._render_text = self.comment_text.replace('\n', '<br>')
        return render_str("comment.html", c=self)


class Handler(webapp2.RequestHandler):
    """ Main handler for the blog, responsible for rendering content"""
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        """ Sets a cookie"""
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie',
                                         '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        """
        Calls the set_secure_cookie function so that the user can remain
        logged in throughout the site
        """
        self.set_secure_cookie('user_id', str(user.key.id()))

    def logout(self):
        """ Removes the cookie for the currently logged in user """
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


# Blog Handlers
class Blog(Handler):
    """ Handles the front of the Blog """
    def get(self):
        posts = Post.query().order(-Post.post_created)
        self.render("front.html", posts=posts, username=self.user)


class AddPost(Handler):
    """ Allows entry of a new post """
    @user_required
    def get(self):
        self.render("new_post.html")

    @user_required
    def post(self):
        """
        Creates a new post if the user is logged in, and provided values
        are valid
        """
        post_title = self.request.get("post_title")
        post_text = self.request.get("post_text")
        created_by = self.user.name
        params = dict(post_title=post_title, post_text=post_text)
        has_error = False
        if not post_title:
            params['title_class'] = "has-error"
            params['title_error'] = "Please add title!"
            has_error = True
        if not post_text:
            params['text_class'] = "has-error"
            params['text_error'] = "Please add content!"
            has_error = True
        if has_error:
            self.render("new_post.html", **params)
        else:
            p = Post(post_title=post_title, post_text=post_text,
                     created_by=created_by)
            p.put()
            self.redirect("/%s" % str(p.key.id()))


class Permalink(Handler):
    """ Allows to each post to have a permalink page"""

    def get(self, post_id):
        post = get_item('Post', post_id)
        comments = get_comments(post_id)
        if not post:
            self.error(404)
            self.render("404.html")
            return

        self.render("permalink.html", p=post, comments=comments)


class EditPost(Handler):
    """ Allows posts to be edited """
    @user_required
    def get(self, post_id):
        post = get_item('Post', post_id)
        if not post:
            self.error(404)
            self.render("404.html")
            return

        if post.created_by == self.user.name:
            self.render('edit_post.html', p=post)
        else:
            error = "You can edit only your posts"
            self.render("error.html", error=error)

    @user_required
    def post(self, post_id):
        """
        Submits changes to the post"""
        post = get_item('Post', post_id)
        if not post:
            self.error(404)
            self.render("404.html")
            return

        if post.created_by == self.user.name:
            post_title = self.request.get("post_title")
            post_text = self.request.get("post_text")
            params = dict(p=post)
            has_error = False
            if not post_title:
                params['title_class'] = "has-error"
                params['title_error'] = "Please add a title!"
                has_error = True
            if not post_text:
                params['text_class'] = "has-error"
                params['text_error'] = "Please add a content!"
                has_error = True
            if has_error:
                self.render("edit_post.html", **params)
            else:
                post.post_title = post_title
                post.post_text = post_text
                post.put()
                self.redirect("/%s" % str(post_id))
        else:
            error = "You can edit only your posts"

            self.render("error.html", error=error)


class DeletePost(Handler):
    """Deleting post and its associated comments"""
    @user_required
    def post(self, post_id):
        post = get_item('Post', post_id)
        if not post:
            self.error(404)
            self.render("404.html")
            return

        if post.created_by == self.user.name:
            ndb.Key('Post', int(post_id)).delete()
            # Deletes the commments associated with the given post
            comments = Comment.query(Comment.post_id == post_id)
            keys = comments.fetch(keys_only=True)
            ndb.delete_multi(keys)
            self.redirect("/")
        else:
            error = "You can delete only your posts"
            self.render("error.html", error=error)


class LikePost(Handler):
    """Post like"""
    @user_required
    def post(self, post_id):
        post = get_item('Post', post_id)
        if not post:
            self.error(404)
            self.render("404.html")
            return

        likes = [l.encode("utf-8") for l in post.likes]
        username = self.user.name
        if username in likes or username == post.created_by:
            self.redirect("/%s" % str(post.key.id()))
        else:
            post.likes.append(username)
            post.put()
            self.redirect("/%s" % str(post.key.id()))


class UnlikePost(Handler):
    """Disliking post"""
    @user_required
    def post(self, post_id):
        """If the user liked the post, removes their like"""
        post = get_item('Post', post_id)
        if not post:
            self.error(404)
            self.render("404.html")
            return

        likes = [l.encode("utf-8") for l in post.likes]
        likes.remove(self.user.name)
        post.likes = likes
        post.put()
        self.redirect("/%s" % str(post.key.id()))


class Welcome(Handler):
    @user_required
    def get(self):
        """ If the user is logged in, renders a welcome page """
        self.render('welcome.html', username=self.user.name)


# User Handlers
class Signup(Handler):
    """Allows to register as a new user"""
    def get(self):
        self.render("signup.html")

    def post(self):
        """Checks if provided info is valid"""
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        has_error = False
        params = dict(username=self.username, email=self.email,
                      password=self.password, verify=self.verify)

        if not valid_username(self.username):
            params['username_error'] = "Not a valid username"
            params['user_class'] = "has-error"
            has_error = True
        if not valid_password(self.password):
            params['password_error'] = "Not a valid password"
            params['pass_class'] = "has-error"
            has_error = True
        elif self.password != self.verify:
            params['verify_error'] = "Passwords do not match"
            params['ver_class'] = "has-error"
            has_error = True
        if not valid_email(self.email):
            params['email_error'] = "Not a valid email"
            params['email_class'] = "has-error"
            has_error = True
        if has_error:
            self.render("signup.html", **params)
        else:
            self.done(params)


class Register(Signup):
    """Regestering new user after Signup form"""
    def done(self, params):
        """
        Checks the provided username already exists, otherwise,
        creates a new User entity
        """
        u = User.by_name(self.username)
        if u:
            params['username_error'] = "This user already exists."
            # This sets the "has-error" class for Bootstrap
            params['user_class'] = "has-error"
            self.render('signup.html', **params)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/')


class Login(Handler):
    """Login handler for registered users"""
    def get(self):
        self.render('login.html')

    def post(self):
        """
        If the provided credentials match credentials stored in the
        User database, the user is logged in
        """
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/welcome')
        else:
            error = 'Invalid login'
            self.render('login.html', error=error)


class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/signup')


# Comment Handlers
class AddComment(Handler):
    """New Comment handler"""
    @user_required
    def post(self, post_id):
        """
        Checks if user is logged in, and the provided values are all valid
        """
        post = get_item('Post', post_id)
        if not post:
            self.error(404)
            self.render("404.html")
            return

        username = self.user.name
        comment_title = self.request.get("comment_title")
        comment_text = self.request.get("comment_text")
        params = dict(comment_title=comment_title,
                      comment_text=comment_text)
        has_error = False
        if not comment_title:
            params['title_class'] = "has-error"
            params['title_error'] = "Please add title to your comment!"
            has_error = True
        if not comment_text:
            params['text_class'] = "has-error"
            params['text_error'] = "please add content to your comment!"
            has_error = True
        if has_error:
            params['post_id'] = post_id
            self.render("new_comment.html", **params)
        else:
            c = Comment(username=username, comment_title=comment_title,
                        comment_text=comment_text, post_id=post_id)
            c.put()
            self.redirect("/%s" % str(post_id))


class EditComment(Handler):
    """"Editing posted comments"""
    @user_required
    def get(self, post_id, comment_id):
        comment = get_item('Comment', comment_id)
        post = get_item('Post', post_id)
        if not post or not comment:
            self.error(404)
            self.render("404.html")
            return

        if comment.username == self.user.name:
            self.render('edit_comment.html', c=comment, p=post)
        else:
            error = "You can edit only your comments"
            self.render("error.html", error=error)

    @user_required
    def post(self, post_id, comment_id):
        comment = get_item('Comment', comment_id)
        post = get_item('Post', post_id)
        if not post or not comment:
            self.error(404)
            self.render("404.html")
            return

        if comment.username == self.user.name:
            comment_title = self.request.get("comment_title")
            comment_text = self.request.get("comment_text")
            params = dict(comment_title=comment_title,
                          comment_text=comment_text, c=comment)
            has_error = False
            if not comment_title:
                params['title_class'] = "has-error"
                params['title_error'] = "Please add title to your comment!"
                has_error = True
            if not comment_text:
                params['text_class'] = "has-error"
                params['text_error'] = "Please add content to your comment!"
                has_error = True
            if has_error:
                params['post_id'] = post_id
                self.render("edit_comment.html", **params)
            else:
                comment.comment_title = self.request.get("comment_title")
                comment.comment_text = self.request.get("comment_text")
                comment.put()
                self.redirect("/%s" % str(post_id))

        else:
            error = "You can edit only your comments"
            self.render("error.html", error=error)


class DeleteComment(Handler):
    """Deleting comments"""
    @user_required
    def post(self, post_id, comment_id):
        comment = get_item('Comment', comment_id)
        post = get_item('Post', post_id)
        if not post or not comment:
            self.error(404)
            self.render("404.html")
            return

        if comment.username == self.user.name:
            ndb.Key('Comment', int(comment_id)).delete()
            self.redirect("/%s" % str(post_id))
        else:
            error = "You can delete your own comments"
            self.render("error.html", error=error)


class LikeComment(Handler):
    """Like comments"""
    @user_required
    def post(self, post_id, comment_id):
        """
        Checks if user didn't created the comment or already liked the comment,
        adds a new like to the comment
        """
        comment = get_item('Comment', comment_id)
        post = get_item('Post', post_id)
        if not post or not comment:
            self.error(404)
            self.render("404.html")
            return

        likes = [u.encode("utf-8") for u in comment.likes]
        username = self.user.name
        if username in likes or username == comment.username:
            self.redirect("/%s" % str(post_id))
        else:
            comment.likes.append(username)
            comment.put()
            self.redirect("/%s" % str(post_id))


class UnlikeComment(Handler):
    """Unlike comments"""
    @user_required
    def post(self, post_id, comment_id):
        """ If the user liked the comment, removes their like """
        comment = get_item('Comment', comment_id)
        post = get_item('Post', post_id)
        if not post or not comment:
            self.error(404)
            self.render("404.html")
            return

        likes = [u.encode("utf-8") for u in comment.likes]
        username = self.user.name
        if username in likes or username == comment.username:
            likes.remove(username)
            comment.likes = likes
            comment.put()
            self.redirect("/%s" % str(post_id))
        else:
            self.redirect("/%s" % str(post_id))


app = webapp2.WSGIApplication([('/', Blog),
                               ('/new_post', AddPost),
                               ('/([0-9]+)', Permalink),
                               ('/([0-9]+)/edit', EditPost),
                               ('/([0-9]+)/delete', DeletePost),
                               ('/([0-9]+)/like', LikePost),
                               ('/([0-9]+)/unlike', UnlikePost),
                               ('/([0-9]+)/add_comment', AddComment),
                               ('/([0-9]+)/([0-9]+)/edit', EditComment),
                               ('/([0-9]+)/([0-9]+)/delete', DeleteComment),
                               ('/([0-9]+)/([0-9]+)/like', LikeComment),
                               ('/([0-9]+)/([0-9]+)/unlike', UnlikeComment),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/welcome', Welcome),
                               ('/logout', Logout)],
                              debug=True)
