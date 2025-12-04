from setuptools import setup, find_packages

setup(
    name="ThinkPHPLogScanner",
    version="1.0.0",
    description="ThinkPHP日志泄露检测与利用工具",
    author="Security Tool Developer",
    author_email="security@example.com",
    packages=find_packages(),
    install_requires=[
        'requests>=2.25.1',
        'beautifulsoup4>=4.9.3',
        'lxml>=4.6.3'
    ],
    entry_points={
        'console_scripts': [
            'thinkphp-scanner=thinkphp_log_scanner:main',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'Topic :: Security',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
    ],
    keywords='thinkphp security scanner log analysis',
    python_requires='>=3.8',
)