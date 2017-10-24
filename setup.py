from setuptools import setup, find_packages
# To use a consistent encoding
from codecs import open
from os import path


try:
    setup(name='teslajson',
          version='1.2.1',
        description='',
        url='https://github.com/gglockner/teslajson',
        py_modules=['teslajson'],
         author='Greg Glockner',
        license='MIT',
        )
except BaseException as e:
    print('CAUGHT')
    print(e)
    print(e.__class__)
