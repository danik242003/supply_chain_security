from setuptools import find_packages, setup

with open("README.md", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="tinyjson",
    version="2.4.1",
    description="Small helpers for JSON documents",
    long_description=long_description,
    packages=find_packages(exclude=["tests"]),
    install_requires=["attrs>=22.0"],
    python_requires=">=3.8",
)
