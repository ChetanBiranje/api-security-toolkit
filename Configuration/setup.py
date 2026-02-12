"""
Setup file for API Security Toolkit
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="api-security-toolkit",
    version="1.0.0",
    author="Chetan Biranje",
    author_email="your.email@example.com",
    description="Comprehensive Python-based security testing framework for REST APIs",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ChetanBiranje/api-security-toolkit",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "api-security-test=api_toolkit:main",
        ],
    },
    keywords="security api testing jwt authentication authorization fuzzing",
    project_urls={
        "Bug Reports": "https://github.com/ChetanBiranje/api-security-toolkit/issues",
        "Source": "https://github.com/ChetanBiranje/api-security-toolkit",
        "Documentation": "https://github.com/ChetanBiranje/api-security-toolkit#readme",
    },
)
