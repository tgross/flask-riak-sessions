# -*- coding: utf-8 -*-
"""
    flask.ext.riaksessions
    ----------------------

    This module provides a Riak-backed session store for Flask sessions.

    :copyright: (c) 2013 Tim Gross
    :license: MIT

"""

__version_info__ = ('0', '1', '0')
__version__ = '.'.join(__version_info__)
__author__ = 'Tim Gross'
__license__ = 'MIT'
__copyright__ = '(c) 2013 Tim Gross'
__all__ = ['RiakSessions', 'RiakSessionInterface', 'RiakSession']

import base64
from datetime import datetime
import hmac
import hashlib
import json
import random
import string
from uuid import uuid4

import riak
from werkzeug.datastructures import CallbackDict
from flask.sessions import SessionInterface, SessionMixin

def generate_hmac(app, content):
    """
    Generates the hash message authentication code (HMAC) using the application
    configuration and the passed content. The content should include a salt.
    Takes the RIAK_SESSIONS_HASH_FUNCTION and SECRET_KEY app config.
    """
    hash_function = app.config['RIAK_SESSIONS_HASH_FUNCTION']
    secret = app.config['SECRET_KEY']
    return base64.b64encode(hmac.new(secret, content, hash_function).digest())

class Encoder(json.JSONEncoder):
    """
    Subclasses JSONEncoder to handle datetimes.
    """

    def default(self, obj):
        """
        Encodes datetime objects in annotated ISO-format:
        '/Date(2013-06-25T23:57:32.779968)/'
        """
        if isinstance(obj, datetime):
            return u'/Date({})/'.format(obj.isoformat())
        return super(Encoder, self).default(self, obj)

def date_hook(data):
    """
    Decodes strings that match the pattern created by the Endoder into datetime
    objects.
    """
    for key, val in data.items():
        if val.startswith('/Date('):
            data[key] = datetime.strptime(val.lstrip('/Date(').rstrip(')/'),
                                          "%Y-%m-%dT%H:%M:%S.%f")
    return data


class RiakSession(CallbackDict, SessionMixin):
    """
    Implements a Flask session that can be HMAC-signed.
    """

    def __init__(self, initial=None, sid=None, new=False):
        def on_update(self):
            """
            Set the dirty-session flag.
            """
            self.modified = True

        CallbackDict.__init__(self, initial, on_update)
        self.sid = sid
        self.new = new
        self.modified = False
        self.hmac_digest = None
        self.salt = None

    def _generate_salt(self, app):
        """
        Creates a salt for use in HMAC.
        """
        rand = random.SystemRandom()
        chars = string.letters + string.digits
        return ''.join(rand.choice(chars) for
                       _ in xrange(app.config['RIAK_SESSIONS_SALT_LENGTH']))

    def sign(self, app):
        """
        Returns a salted HMAC of the session identifier (from the cookie), for
        use in comparing it against a value stored in the session store.
        """
        if not self.hmac_digest:
            self._generate_salt(app)
            self.hmac_digest = generate_hmac(app, '{}:{}'.format(self.sid,
                                                                 self.salt))



class RiakSessionInterface(SessionInterface):
    """
    Implements a Flask session interface that uses Riak as the backing store
    and HMAC-signs the session cookie.
    """

    def __init__(self, app, client=None):
        if client is None:
            client = riak.RiakClient(port=app.config['RIAK_HTTP_PORT'])
        self.client = client

    def generate_sid(self):
        """
        Unique session ID.
        """
        return str(uuid4())

    def put(self, app, session):
        """
        Stores the session data and HMAC signature in the Riak datastore.
        """
        session.sign(app)
        session_bucket = self.client.bucket('sessions')
        session_object = session_bucket.new(session.sid,
                                            (session.hmac_digest,
                                             json.dumps(dict(session),
                                                        cls=Encoder)))
        session_object.store()

    def get(self, sid, cookie_hmac):
        """
        Gets the session data from the Riak datastore and compares the HMAC
        signatures of the session ID to ensure it has been not been altered.
        """
        session_bucket = self.client.bucket('sessions')
        serialized_session = session_bucket.get(sid)
        if serialized_session:
            stored_hmac, data = serialized_session.get_data()
            if data:
                if stored_hmac == cookie_hmac:
                    session = json.loads(data, object_hook=date_hook)
                    return session
                else:
                    raise Exception('Tampered session!')
        return RiakSession()

    def open_session(self, app, request):
        """
        Fetch the session from the Riak database based using the session cookie
        key or create a new session.

        """
        cookie = request.cookies.get(app.session_cookie_name)
        if not cookie or not '!' in cookie:
            sid = self.generate_sid()
            return RiakSession(sid=sid, new=True)

        sid, digest = cookie.split('!', 1)
        session_data = self.get(sid, digest)
        if session_data:
            return RiakSession(session_data, sid=sid)

        return RiakSession(sid=sid, new=True)

    def save_session(self, app, session, response):
        """
        This will be called by Flask during request teardown.  Saves the session
        if it has been modified.  Currently does not expire cookie.

        """
        domain = self.get_cookie_domain(app)
        if not session:
            if session.modified:
                response.delete_cookie(app.session_cookie_name, domain)
            return None

        if not session.modified:
            return

        self.put(app, session)
        cookie_contents = '{}!{}'.format(session.sid, session.hmac_digest)
        response.set_cookie(app.session_cookie_name, cookie_contents,
                            expires=self.get_expiration_time(app, session),
                            httponly=self.get_cookie_httponly(app),
                            secure=self.get_cookie_secure(app),
                            domain=domain)


class RiakSessions(object):
    """
    Sets up the Flask-RiakSessions extension during application startup.
    Instantiate this class and pass the application to the `app` argument to
    set it up.

    """
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """
        Sets up default config variables and instantiates the session interface.

        """
        app.config.setdefault('RIAK_BIN_DIR',
                              '/Users/tgross/lib/riak-1.3.2/rel/riak/bin')
        app.config.setdefault('RIAK_HTTP_PORT', 10018)
        app.config.setdefault('RIAK_PROTOBUFS_PORT', 9001)
        app.config.setdefault('RIAK_SESSIONS_HASH_FUNCTION', hashlib.sha256)
        app.config.setdefault('RIAK_SESSIONS_SALT_LENGTH', 20)

        app.session_interface = RiakSessionInterface(app)
