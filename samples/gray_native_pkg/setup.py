import os
import tarfile
import urllib.request
from setuptools import setup
from setuptools.command.install import install

RELEASE = "https://github.example/fastgeo/releases/download/v3.1.0/fastgeo-bin.tar.gz"


class FetchBinaries(install):
    """Download the prebuilt geometry kernel for this platform."""

    def run(self):
        target = os.path.join(self.build_lib or "build", "fastgeo", "bin")
        os.makedirs(target, exist_ok=True)
        archive, _ = urllib.request.urlretrieve(RELEASE)
        with tarfile.open(archive) as tar:
            tar.extractall(target)
        install.run(self)


setup(name="fastgeo", version="3.1.0", packages=["fastgeo"], cmdclass={"install": FetchBinaries})
