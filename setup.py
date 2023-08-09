from setuptools import setup, find_packages

setup(
    name='shush',
    version='0.0.1a0',
    python_requires='>=3.9',
    packages=find_packages(),
    package_data={'shush': ['rules/*.yar']},
    include_package_data=True,
    description='Uncover credentials, API tokens, and other sensitive content in your Slack instance.',
    keywords='slack secrets api credentials tokens',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Topic :: Security',
        'Topic :: System :: Monitoring',
        'Topic :: Communications :: Chat',
        'Topic :: Utilities',
        'Programming Language :: Python :: 3',
    ],
    install_requires=[
        'colorama',
        'pony',
        'slackclient',
        'tqdm',
        'yara-python',
    ],
    entry_points={
        'console_scripts': [
            'shush=shush.cli.main'
        ]
    }
)