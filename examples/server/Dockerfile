# Supply a registry-qualified, digest-pinned Node image from the approved image catalog.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
WORKDIR /app
COPY --chown=1000:1000 server.js healthcheck.js ./
USER 1000:1000
EXPOSE 8080
CMD ["node", "server.js"]
