import setuptools

long_description = \
"""# Proveth

Proveth is a library for generating and verifying Merkle-Patricia-proofs for Ethereum.
Proveth provides an off-chain proof generator & verifier (in this python package),
an on-chain proof verifier (a smart contract), and a specification of the proof format.

For more details, see https://github.com/lorenzb/proveth.
"""

setuptools.setup(
    name="proveth",
    version="0.0.2",
    author="Lorenz Breidenbach",
    author_email="lorenzb@ethz.ch",
    description="Generate & verify Merkle-Patricia-proofs for Ethereum",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/lorenzb/proveth",
    packages=setuptools.find_packages(),
    classifiers=(
        "Development Status :: 3 - Alpha",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security :: Cryptography",
    ),
)
