FROM registry.access.redhat.com/ubi10/ubi-minimal:latest
LABEL org.opencontainers.image.title="saros"
LABEL org.opencontainers.image.description="inex firmware registry"
COPY saros /usr/local/bin/saros
EXPOSE 8080
VOLUME /data
CMD ["saros"]
