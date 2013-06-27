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
import logging
import os
from uuid import uuid4

import riak
from werkzeug.datastructures import CallbackDict
from flask.sessions import SessionInterface, SessionMixin

# shut up about short parameter names
# pylint: disable=C0103
LOG = logging.getLogger(__name__)

def get_hmac(app, content):
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

class SessionValidationError(Exception):
    """
    Raised in the event a session id cannot be validated and should ignored.
    """
    pass


class RiakSession(CallbackDict, SessionMixin):
    """
    Implements a Flask session that can be HMAC-signed.
    """

    def __init__(self, initial=None, sid=None, token=None, new=False, expiry=None):
        def on_update(self):
            """
            Set the dirty-session flag.
            """
            self.modified = True

        CallbackDict.__init__(self, initial, on_update)
        self.sid = sid
        self.token = token
        self.new = new
        self.modified = False
        self.expiry = expiry

    @property
    def key(self):
        return '{}!{}'.format(self.token, self.sid)


class RiakSessionInterface(SessionInterface):
    """
    Implements a Flask session interface that uses Riak as the backing store
    and HMAC-signs the session cookie.
    """

    def __init__(self, app, client=None):
        if client is None:
            client = riak.RiakClient(port=app.config['RIAK_HTTP_PORT'])
        self.client = client

    def generate_sid(self, app, ip, user_agent):
        """
        Uses the IP and user-agent as the inputs to an HMAC to be used as the
        unique session ID.

        """
        sid = get_hmac(app, '{}.{}'.format(ip, base64.b64encode(user_agent)))
        return sid


    def put(self, session):
        """
        Stores the session data and expiry time in the Riak datastore.

        """
        session_bucket = self.client.bucket('sessions')
        session_object = session_bucket.new(session.key,
                                            (session.expiry,
                                             json.dumps(dict(session),
                                                        cls=Encoder)))
        session_object.store()

    def get(self, cookie, app, ip, user_agent):
        """
        Gets the session data from the Riak datastore and compares the HMAC
        signatures of the IP and User-Agent against the session ID to ensure
        it has not been altered.

        """
        sid = self.generate_sid(app, ip, user_agent)
        token, cookie_sid = cookie.split('!', 1)

        if cookie_sid != sid:
            raise SessionValidationError('Tampered session.')

        session_bucket = self.client.bucket('sessions')
        stored_value = session_bucket.get(cookie)
        if stored_value:
            expiry, serialized = stored_value.get_data()
            if serialized and (expiry is None or expiry > datetime.now()):
                data = json.loads(serialized, object_hook=date_hook)
                return RiakSession(data, sid=sid, token=token, expiry=expiry)

        session = RiakSession(sid=sid, token=uuid4(), new=True)
        session.expiry = self.get_expiration_time(app, session)
        return session


    def open_session(self, app, request):
        """
        Fetch the session from the Riak database after validating the session ID
        or create a new session ID + session.

        """
        cookie = request.cookies.get(app.session_cookie_name)
        ip = request.remote_addr
        # Flask test server has no User-Agent, so return safe value here
        user_agent = request.headers.get('User-Agent', 'NULL')

        if cookie:
            try:
                session = self.get(cookie, app, ip, user_agent)
                return session
            except SessionValidationError:
                # we'll just pass and generate a new session
                LOG.exception('Invalid session')

        sid = self.generate_sid(app, ip, user_agent)
        session = RiakSession(sid=sid, token=uuid4(), new=True)
        session.expiry = self.get_expiration_time(app, session)
        return session


    def save_session(self, app, session, response):
        """
        This will be called by Flask during request teardown.  Saves the session
        if it has been modified.

        """
        domain = self.get_cookie_domain(app)
        if not session:
            response.delete_cookie(app.session_cookie_name, domain)
            return

        if not session.modified:
            return

        self.put(session)
        cookie_contents = session.key
        response.set_cookie(app.session_cookie_name, cookie_contents,
                            expires=session.expiry,
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
        app.config.setdefault('RIAK_BIN_DIR', os.environ.get('RIAK_DIR',''))
        app.config.setdefault('RIAK_HTTP_PORT', 10018)
        app.config.setdefault('RIAK_PROTOBUFS_PORT', 9001)
        app.config.setdefault('RIAK_SESSIONS_HASH_FUNCTION', hashlib.sha256)

        app.session_interface = RiakSessionInterface(app)
