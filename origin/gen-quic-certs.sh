#!/usr/bin/env bash

# Copyright (c) Meta Platforms, Inc. and affiliates.
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# copied from moxygen repository

# Generate public - private key
openssl req -newkey rsa:2048 -nodes -keyout ../secrets/certificate.key -x509 -out ../secrets/certificate.pem -subj '/CN=Test Certificate' -addext "subjectAltName = DNS:localhost"
