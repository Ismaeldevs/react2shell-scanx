"""
Setup configuration for react2shell-scanner package.
"""
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="react2shell-scanner",
    version="2.0.0",
    author="Assetnote Security Research Team",
    description="High Fidelity Detection for RSC/Next.js RCE (CVE-2025-55182 & CVE-2025-66478)",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/assetnote/react2shell-scanner",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.9",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "react2shell-scanner=src.cli.main:main",
        ],
    },
)
