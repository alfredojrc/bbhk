"""Setup configuration for the Bug Bounty Hunting Framework."""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text() if readme_path.exists() else ""

# Read requirements
requirements_path = Path(__file__).parent / "requirements.txt"
requirements = requirements_path.read_text().splitlines() if requirements_path.exists() else []

setup(
    name="bug-bounty-framework",
    version="1.0.0",
    author="Bug Bounty Framework Team",
    author_email="contact@example.com",
    description="A comprehensive automation framework for ethical bug bounty hunting",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/bug-bounty-framework",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
    ],
    python_requires=">=3.11",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.4.3",
            "pytest-asyncio>=0.21.1",
            "pytest-cov>=4.1.0",
            "black>=23.0.0",
            "isort>=5.12.0",
            "flake8>=6.0.0",
            "mypy>=1.5.0",
        ],
        "ml": [
            "tensorflow>=2.18.0",
            "torch>=2.5.0",
            "transformers>=4.47.0",
        ],
        "browser": [
            "selenium>=4.16.2",
            "playwright>=1.40.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "bbhk=src.main:cli",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)