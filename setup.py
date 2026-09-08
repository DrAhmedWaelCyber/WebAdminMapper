"""
WebAdminMapper - Installation Script
====================================
Setup configuration for packaging and distribution.

Developer & Author: Ahmed Wael
Copyright (c) 2026, Ahmed Wael. All rights reserved.
"""

from setuptools import find_packages, setup

setup(
    name="webadminmapper",
    version="1.1.0",
    author="Ahmed Wael",
    author_email="ahmedwael6143@gmail.com",

    description="A professional multi-file Python utility for web administration, directory mapping, and file structure discovery.",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "web_mapper": ["wordlists/*.txt"],
    },
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "webadminmapper = web_mapper.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
    ],
)
