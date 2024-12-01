FROM ubuntu:24.04@sha256:278628f08d4979fb9af9ead44277dbc9c92c2465922310916ad0c46ec9999295

RUN apt update && apt install -y socat

WORKDIR /

COPY aquarius /aquarius

CMD ["socat", "TCP-LISTEN:7117,reuseaddr,fork", "EXEC:/aquarius"]
