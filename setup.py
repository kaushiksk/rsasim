from setuptools import setup


def readme():
    with open('README.md') as f:
        return f.read()


setup(name='rsasim',
      version='0.1',
      description='A simple pure python implementation of RSA',
      long_description=readme(),
      url='https://github.com/kaushiksk/rsasim',
      author='Kaushik S Kalmady',
      author_email='kaushikskalmady@yahoo.in',
      license='MIT',
      packages=['rsasim'],
      scripts=['bin/isprime', 'bin/genprime'],
      include_package_data=True,
      zip_safe=False)
