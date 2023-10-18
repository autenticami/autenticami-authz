# Build Stage
FROM golang:1.20.7 AS BuildStage
LABEL maintainer="Nitro Agility S.r.l. Team <opensource@nitroagility.com>"

COPY ./cmd /app/cmd
COPY ./pkg /app/pkg
COPY ./scripts /app/scripts
COPY ./go.mod /app/go.mod
COPY ./go.sum /app/go.sum
COPY ./LICENSE /app/LICENSE
COPY ./Makefile /app/Makefile
WORKDIR /app
RUN /bin/bash ./scripts/build.sh

# Build Official Image
FROM alpine
LABEL maintainer="Nitro Agility S.r.l. Team <opensource@nitroagility.com>"

ARG USER=nonroot
ENV HOME /home/$USER

RUN apk add --update sudo
RUN adduser -D $USER \
        && echo "$USER ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/$USER \
        && chmod 0440 /etc/sudoers.d/$USER
USER $USER

WORKDIR /home/$USER
COPY --from=BuildStage /app/autenticami ./

ENTRYPOINT ["/home/$USER/autenticami"]
