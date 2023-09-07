ARG BASE_IMAGE
FROM ${BASE_IMAGE:-scratch}

COPY plugin.so /plugin.so