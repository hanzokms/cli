FROM alpine
RUN apk add --no-cache tini
COPY kms /bin/kms
ENTRYPOINT ["/sbin/tini", "--", "/bin/kms"]
