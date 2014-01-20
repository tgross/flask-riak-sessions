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

from datetime import datetime
import hashlib
import logging
import os
import string
import time

from riak import RiakClient
from werkzeug.datastructures import CallbackDict
from flask.sessions import SessionInterface, SessionMixin, TaggedJSONSerializer

LOG = logging.getLogger(__name__)

# borrowed from Django; we use the system PRNG
# if its present and otherwise fallback
import random
try:
    random = random.SystemRandom()
    USING_SYSRANDOM = True
except NotImplementedError:
    import warnings
    warnings.warn('A secure pseudo-random number generator is not available '
                  'on your system. Falling back to Mersenne Twister.')
    USING_SYSRANDOM = False


class InvalidSession(Exception):
    """
    Raised in the event a session ID can't be found in the
    datastore and we want to mark it as a suspicious operation.

    """
    pass

class ExpiredSession(Exception):
    """
    Raised in the event a session ID has expired and we want
    to clear it.

    """
    pass



class RiakSession(CallbackDict, SessionMixin):
    """
    Implements a Flask session

    """
    def __init__(self, initial=None, token=None, expiry=None):
        def on_update(self):
            """ Set the dirty-session flag. """
            self.modified = True

        CallbackDict.__init__(self, initial, on_update)
        self.modified = False
        self.token = token
        self.expiry = expiry



class RiakSessionInterface(SessionInterface):
    """
    Implements a Flask session interface that uses Riak as the backing store.
    Watch out for the mutability of the session object if you extend this
    class; the superclass relies on this. The serializer and session_class
    have been made class attributes so that you can override the behavior
    of e.g. the serializer.

    """
    serializer = TaggedJSONSerializer()
    session_class = RiakSession

    def __init__(self, app, client=None):
        self.bucket = app.config['RIAK_SESSION_BUCKET']
        if client is None:
            config = app.config['RIAK_SESSION_CONN']
            client = RiakClient(**config)
        self.client = client

    def _generate_token(self):
        """
        Generate a random session token. Borrows Django's approach
        of re-seeding the PRNG with a difficult-to-predict value
        when a system PRNG isn't available.

        """
        valid_token_chars = string.ascii_lowercase + string.digits
        if not USING_SYSRANDOM:
            seed_input = ("%s%s%s" % (random.getstate(),
                                      time.time(),
                                      self.app.config['SECRET_KEY']))
            random.seed(hashlib.sha256(seed_input.encode('utf-8')).digest())
        return ''.join(random.choice(valid_token_chars) for i in range(32))


    def _put(self, session):
        """
        Stores the session data and expiry time in the Riak datastore.

        """
        if not session.token:
            # be lazy about generating keys
            session.token = self._generate_token()
        if not session.expiry:
            now = datetime.utcnow() + self.app.permanent_session_lifetime
            session.expiry = time.mktime(now.timetuple())
        session_bucket = self.client.bucket(self.bucket)
        session_object = session_bucket.new(session.token,
                                            (session.expiry,
                                             self.serializer.dumps(session)))
        session_object.store()

    def _get(self, token):
        """
        Gets the session data from the Riak datastore.
        Deserializes it and returns a RiakSession object. Raises an
        ExpiredSession or InvalidSession exception in the event
        the session is bad.

        """
        session_bucket = self.client.bucket(self.bucket)
        # look at whether this is a possible timing attack here w/ Riak?
        stored_data = session_bucket.get(token)
        if stored_data:
            expiry, serialized = stored_data.get_encoded_data()
            if serialized:
                if expiry and (expiry <= time.mktime(datetime.utcnow().timetuple())):
                    session_bucket.delete(token)
                    raise ExpiredSession()
                data = self.serializer.loads(serialized)
                return RiakSession(data, token=token, expiry=expiry)

        raise InvalidSession()

    def should_set_cookie(self, app, session):
        """
        We should set the cookie if the app is configured to do
        so every time or if the session is currently dirty.
        """
        if app.config.get('SESSION_REFRESH_EACH_REQUEST', False):
            return True
        if session.modified:
            return True
        return False

    def open_session(self, app, request):
        """
        Fetch the session from the Riak database or create a new
        session ID and session.

        """
        self.app = app
        token = request.cookies.get(app.session_cookie_name)
        if token:
            try:
                session = self._get(token)
                return session
            except (ExpiredSession, InvalidSession):
                # don't want hostile tokens showing up in prod logs
                LOG.debug('Invalid or expired session token: {}'.format(token))
        return self.session_class()


    def save_session(self, app, session, response):
        """
        This will be called by Flask during request teardown.  Saves the
        session if it has been modified.

        """
        self.app = app
        domain = self.get_cookie_domain(app)
        path = self.get_cookie_path(app)

        # delete the session and bail-out
        if not session:
            if session.modified:
                response.delete_cookie(app.session_cookie_name,
                                       domain=domain, path=path)
            return

        # controlled by SESSION_REFRESH_EACH_REQUEST config flag and
        # flag on the session
        if not self.should_set_cookie(app, session):
            return

        httponly = self.get_cookie_httponly(app)
        secure = self.get_cookie_secure(app)
        expires = self.get_expiration_time(app, session)

        self._put(session)
        cookie_val = session.token

        response.set_cookie(app.session_cookie_name, cookie_val,
                            httponly=httponly, secure=secure, expires=expires,
                            domain=domain, path=path)


class RiakSessions(object):
    """
    Sets up the Flask-RiakSessions extension during application startup.
    Use in main application module as follows:

    app = Flask(__name__)
    RiakSessions(app)

    """
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """
        Sets up default config variables and instantiates the session
        interface. RIAK_SESSION_NODES takes any value that can be passed
        as kwargs to a RiakClient. See:
        http://basho.github.io/riak-python-client/client.html#client-connections

        """
        app.config.setdefault('RIAK_SESSION_CONN',
                              {'nodes': [{'host':'127.0.0.1',
                                          'http_port':8098}]})
        app.config.setdefault('RIAK_SESSION_BUCKET', 'sessions')
        app.config.setdefault('RIAK_BIN_DIR', os.environ.get('RIAK_DIR', ''))
        app.session_interface = RiakSessionInterface(app)
