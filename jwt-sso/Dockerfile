FROM golang:alpine as builder
ADD ./ /weave
RUN cd /weave && \
    go build -mod=vendor

FROM alpine
COPY --from=builder /weave/weave /
COPY --from=builder /weave/test /test/
COPY --from=builder /weave/config /config/
ENTRYPOINT ["/weave"]
