# Copyright 2022 The OWASP Coraza contributors
# SPDX-License-Identifier: Apache-2.0

ARG BASE_IMAGE
FROM ${BASE_IMAGE:-scratch}

COPY plugin.so /plugin.so