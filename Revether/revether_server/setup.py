import setuptools

setuptools.setup(
    name="revether_server",
    version="0.0.1",
    author="Revether",
    packages=setuptools.find_packages(),
    python_requires='>=2.7',
    install_requires=[
        'construct==2.9.45',
    ],
    entry_points={
        'console_scripts': [
            'revether_server=revether_server.main:main'
        ],
    }
)
