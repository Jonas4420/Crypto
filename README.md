# C++ Cryptographic library

[![Build Status](https://travis-ci.com/Jonas4420/Crypto.svg?branch=master)](https://travis-ci.com/Jonas4420/Crypto)
[![codecov](https://codecov.io/gh/Jonas4420/Crypto/branch/master/graph/badge.svg)](https://codecov.io/gh/Jonas4420/Crypto)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

C++ cryptographic library for fun and profit.\
**WARNING: _Use at your own risk as it is purely amateur project._**

This project is licensed under the MIT License - see the LICENSE file for details.

## Description 
Initial goal of this project was to provide Cryptographic primitives for a Bitcoin library.\
As the development advanced, it also implemented other algorithms (basically trying to have Suite-B's algorithms), so a split occured from the initial project.

Second objective of the project is to experiment development tools, on a medium sized project (Git, Travis-CI, AddressSanitizer, ...).

## Build and dependencies

A CMake file is provided for building the entire library, and version 3.1 is expected at minimum.\
It can run for GNU g++ and LLVM Clang (Unix and Apple version supported).\
Windows' compilers (Visual Studio or MinGW) have not been included in the build chain.

The available build types for CMake are:
 * `Release`: optimization on (-O2)
 * `Debug`: optimization off, debug on (-g3)
 * `ASan`: optimization on (-O2), debug on (-g3), compile with AddressSanitizer modules (for g++ or Clang)
 * `Coverage`: optimization off, debug on (-g3), coverage information on, using lcov

It is possible to build the project by other means, as the build chain is not really complex.\
The library tries to keep the different cryptographic modules as independant as possible from each other.

It might be necessary for some objects to have different headers for interfaces, or to include also other object for higher level objects (such as ASN1 parser requires to also compile OID objects or BigNum)

The library is made for C++11, and hence, expect to have a C++11 standard library available.\
There is no additional library needed to build the project.

## Testing

The testing is available through CTest, using googletest for unit testing.\
valgrind is added in CMake build chain as a memchecker for CTest.

The project is integrated to Travis-CI for continuous integration.\
Tested platforms are Linux and OSX, only on 64 bits architectures.

# Credits

## Cryptography implementations

These libraries have been used as reference during the development process:
 * [Botan](https://botan.randombit.net)
 * [Crypto++](https://www.cryptopp.com)
 * [Mbed TLS](https://tls.mbed.org)
 * [OpenSSL](https://www.openssl.org)
 * [Serpent](https://www.ii.uib.no/~osvik/serpent/)

## Development tools
 * [Badges](https://gist.github.com/lukas-h/2a5d00690736b4c3a7ba)
 * [googletest integration](https://crascit.com/2015/07/25/cmake-gtest/)
 * [Project structure](https://github.com/codecov/example-cpp11-cmake/)
 * [Travis-CI](https://juan-medina.com/2017/07/01/moderncppci/)
