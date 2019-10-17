import setuptools

setuptools.setup(
    name="revether_common",
    version="0.0.1",
    author="Revether",
    packages=setuptools.find_packages(),
    python_requires='>=2.7',
    install_requires=[
        'construct==2.9.45'
    ]
)
