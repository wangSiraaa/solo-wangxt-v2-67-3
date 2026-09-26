FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /bin/registry-server ./cmd/server \
 && CGO_ENABLED=0 go build -o /bin/registryctl ./cmd/registryctl

FROM alpine:3.20
COPY --from=build /bin/registry-server /usr/local/bin/registry-server
COPY --from=build /bin/registryctl /usr/local/bin/registryctl
EXPOSE 8080
ENTRYPOINT ["registry-server"]
