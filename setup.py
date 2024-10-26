from setuptools import setup, find_packages

setup(
    name='DeauthVen0m',
    version='1.1',
    author='root0emir', 
    description='Advanced WiFi Deauth Attack Tool',
    long_description=open('README.md').read(),  
    long_description_content_type='text/markdown',
    url='https://github.com/root0emir/deauthven0m',  
    packages=find_packages(),
    install_requires=[
        'scapy',
        'colorama',
        'pyfiglet',
    ],
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
    entry_points={
        'console_scripts': [
            'deauthven0m=deauthven0m:main',  
        ],
    },
)
