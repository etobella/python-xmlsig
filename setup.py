from setuptools import find_packages, setup

install_requires = [
    "lxml>=3.0.0",
    "cryptography",
]

tests_require = [
    "freezegun==0.3.8",
    "mock==2.0.0",
    "pretend==1.0.8",
    "pytest-cov==2.5.1",
    "pytest==3.1.3",
    "requests_mock>=0.7.0",
    "PyOpenSSL",
    "isort==4.2.5",
    "flake8==3.3.0",
    "flake8-blind-except==0.1.1",
    "flake8-debugger==1.4.0",
    "flake8-imports==0.1.1",
]


setup(
    name="xmlsig",
    version="1.0.1",
    description="Python based XML signature",
    long_description="XML Signature created with cryptography and lxml",
    author="Enric Tobella Alomar",
    author_email="etobella@creublanca.es",
    url="http://github.com/etobella/python-xmlsig",
    install_requires=install_requires,
    tests_require=tests_require,
    extras_require={"test": tests_require},
    entry_points={},
    package_dir={"": "src"},
    packages=find_packages("src"),
    include_package_data=True,
    license="LGPL-3",
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: GNU Affero General Public License v3",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: Implementation :: PyPy",
    ],
    zip_safe=False,
)
