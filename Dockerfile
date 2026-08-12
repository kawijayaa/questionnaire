FROM python:3.14-alpine AS builder

WORKDIR /app

COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

FROM python:3.14-alpine

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PATH=/home/questionnaire/.local/bin:$PATH

WORKDIR /app

RUN apk add --no-cache socat

RUN adduser -D questionnaire
COPY --from=builder /root/.local /home/questionnaire/.local
RUN chown -R questionnaire:questionnaire /home/questionnaire/.local

# Copy the server and default config
COPY server.py config.yaml ./

# Notice we DO NOT chown /app to 'questionnaire'. 
# Leaving it as root (read-only to the user) prevents an attacker 
# who gains RCE from modifying the server script or config.
USER questionnaire

EXPOSE 1337

# Limit idle sessions and concurrent children. stderr and echo=0 avoid hidden
# errors and duplicate terminal input.
CMD ["socat", "-T60", "TCP-LISTEN:1337,reuseaddr,fork,max-children=100", "EXEC:'python server.py',pty,stderr,echo=0"]
