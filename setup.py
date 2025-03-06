from setuptools import setup, find_packages

setup(
    name="wifi_monitor",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        'boto3',
    ],
    author="Biswajit Pain",
    author_email="biswajit.pain@outlook.com",
    description="A package to monitor Wi-Fi and update AWS security groups",
    long_description=open('README.md').read(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/wifi_monitor",
)