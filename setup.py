from setuptools import setup, find_packages

with open("requirements.txt") as f:
	install_requires = f.read().strip().split("\n")

# get version from __version__ variable in zatca_amaken/__init__.py
from zatca_amaken import __version__ as version

setup(
	name="zatca_amaken",
	version=version,
	description="zatca",
	author="amaken",
	author_email="hd",
	packages=find_packages(),
	zip_safe=False,
	include_package_data=True,
	install_requires=install_requires
)
