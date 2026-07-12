FROM python:3.12-slim
WORKDIR /srv
COPY pyproject.toml README.md ./
COPY src ./src
COPY app ./app
RUN pip install --no-cache-dir ".[web]"
EXPOSE 7860
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "7860"]
