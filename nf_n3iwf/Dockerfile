FROM zhria/n3iwfcustom:latest as builder 
FROM alpine:3.15

LABEL description="Free5GC open source 5G Core Network" \
    version="KPMv3.0-RCv1.0.3"

ENV F5GC_MODULE=n3iwf

#ARG DEBUG_TOOLS
RUN apk update
# Install debug tools ~ 100MB
RUN apk add --no-cache vim strace net-tools curl netcat-openbsd

# Install N3IWF dependencies
RUN apk add --no-cache iproute2 util-linux

# Set working dir
WORKDIR /free5gc
RUN mkdir -p config/ log/ cert/

# Copy executable and default certs #Copia tutto dalla immagine n3iwf_local dentro la directory free5gc
COPY --from=builder /free5gc/${F5GC_MODULE}/ .

# Config files volume
VOLUME [ "/free5gc/config" ]

# Certificates (if not using default) volume
VOLUME [ "/free5gc/cert" ]
