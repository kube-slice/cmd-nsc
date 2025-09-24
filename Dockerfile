FROM golang:1.24 as go
ENV GO111MODULE=on
ENV CGO_ENABLED=0
ENV GOBIN=/bin
RUN go install github.com/go-delve/delve/cmd/dlv@v1.8.2
#ADD https://github.com/spiffe/spire/releases/download/v1.2.2/spire-1.2.2-linux-x86_64-glibc.tar.gz .
#RUN tar xzvf spire-1.2.2-linux-x86_64-glibc.tar.gz -C /bin --strip=2 spire-1.2.2/bin/spire-server spire-1.2.2/bin/spire-agent

FROM go as build
ARG TARGETPLATFORM
ARG TARGETARCH
WORKDIR /build
COPY go.mod go.sum ./
#COPY ./internal/imports imports
#RUN go build ./imports
ADD vendor vendor
COPY . .
RUN go env -w GOPRIVATE=github.com/kubeslice && \
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} GO111MODULE=on go build -mod=vendor -a -o /bin/app .

#RUN go build -o /bin/app .

FROM build as test
CMD go test -test.v ./...

FROM test as debug
CMD dlv -l :40000 --headless=true --api-version=2 test -test.v ./...

FROM alpine:3.20.1 as runtime
COPY --from=build /bin/app /bin/app
ENTRYPOINT ["/bin/app"]
