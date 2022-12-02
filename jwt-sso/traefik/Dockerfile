FROM alpine:3
ARG PLUGIN_MODULE=github.com/aseara/jc2h
ARG PLUGIN_GIT_REPO=https://github.com/aseara/jc2h.git
ARG PLUGIN_GIT_BRANCH=master
RUN apk add --update git && \
    git clone ${PLUGIN_GIT_REPO} /plugins-local/src/${PLUGIN_MODULE} \
          --depth 1 --single-branch --branch ${PLUGIN_GIT_BRANCH}

FROM traefik:2.9.1
COPY --from=0 /plugins-local /plugins-local