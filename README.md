# questionnaire

![Screenshot](assets/screenshot.png)

```bash
docker run -d \
    --name questionnaire \
    -p 1337:1337 \
    -v $(pwd)/config.yaml:/app/config.yaml \
    ghcr.io/kawijayaa/questionnaire
```

A configurable questionnaire program designed for CTF challenges that requires users to answer questions to solve the challenge. Supports multi-answer questions, unordered list-based answers and case insensitivity.

## Local Development

```bash
git clone https://github.com/kawijayaa/questionnaire
cd questionnaire
pip install -r requirements.txt
python server.py
```
