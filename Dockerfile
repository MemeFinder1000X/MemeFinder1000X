FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY *.py ./

# Apply the read-only security integration before starting the bot.
# This keeps the container/Railway path aligned with local startup.
CMD ["sh", "-c", "python apply_security_integration.py && exec python bot.py"]
