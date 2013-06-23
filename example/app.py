"""
A trivial example application of how to setup and use Flask-RiakSessions.
Assumes you have a Riak instance running.
"""

from datetime import datetime

from flask import Flask, session, request
from flask.ext.riaksessions import RiakSessions

app = Flask(__name__)
app.config.from_object(__name__)
app.debug = True
app.config['SECRET_KEY'] = 'mysecretkey'
RiakSessions(app)


@app.route('/')
def hello():
    previous_visit = session.get('last_visit', False)
    last_ip = session.get('ip', False)
    session['last_visit'] = datetime.now()
    session['ip'] = request.remote_addr
    if not previous_visit:
        return 'Hello, stranger from {}'.format(request.remote_addr)
    return 'Hello, your last visit was {} from {}'.format(previous_visit, last_ip)


if __name__ == '__main__':
    app.run()
