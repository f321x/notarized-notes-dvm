FROM python:3.14-slim

RUN apt-get update && apt-get install -y git libsecp256k1-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .
ENV ELECTRUM_ECC_DONT_COMPILE=1
RUN pip install --no-cache-dir -r requirements.txt

CMD ["python", "main.py"]

# build with:
# docker build -t notarized-notes-dvm .
# run with:
# docker run --restart unless-stopped --env-file .env notarized-notes-dvm