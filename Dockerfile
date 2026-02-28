FROM python:3.14-alpine AS builder

WORKDIR /app

COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

FROM python:3.14-alpine

WORKDIR /app

RUN apk add --no-cache socat

RUN adduser -D questionnaire
COPY --from=builder /root/.local /home/questionnaire/.local
COPY server.py .

RUN chown -R questionnaire:questionnaire /app /home/questionnaire/.local

ENV PATH=/home/questionnaire/.local/bin:$PATH

USER questionnaire

EXPOSE 1337

CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:'python -u server.py',pty"]
