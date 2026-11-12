# Outwit: the guard service + the arena, in one container.
# Runs on Hugging Face Spaces (Docker), Render, Railway, Fly.io or any Docker host.
# Secrets come from the environment, never the image:
#   OUTWIT_CONFIG  the contents of outwit.json (written by chain/setup.mjs)
#   LLM_API_KEY, LLM_BASE_URL, LLM_MODEL  Keeper's model (optional)
FROM node:22-bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Hugging Face Spaces run the container as user 1000.
RUN useradd -m -u 1000 outwit || true
WORKDIR /app

COPY chain/package.json chain/package-lock.json chain/
RUN cd chain && npm ci --omit=dev

COPY *.py arena.html ./
COPY chain/*.mjs chain/
RUN chown -R 1000:1000 /app
USER 1000

ENV PORT=7860 HOST=0.0.0.0 PYTHONUNBUFFERED=1
EXPOSE 7860
CMD ["python3", "arena.py"]
