"""
Flask-RiakSessions
-------------------

This extension implements a Riak session store for Flask.
"""
from setuptools import setup

setup(
    name='Flask-RiakSessions',
    version='0.1a',
    url='http://github.com/tgross/flask-riak-sessions',
    license='MIT',
    author='Tim Gross',
    author_email='tim@0x74696d.com',
    long_description=__doc__,
    py_modules=['flask_riaksessions'],
    zip_safe=False,
    include_pacakge_data=True,
    platforms='any',
    install_requires=[
        'Flask',
        'riak',
        ],
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
        ]
    )
