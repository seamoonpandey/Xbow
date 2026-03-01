FROM python:3.11-slim

WORKDIR /app

# when build context is ./modules, copy requirements from subdirectory
COPY payload-gen-module/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# copy module source
COPY payload-gen-module/ .

# copy shared schemas (sibling directory in build context)
COPY shared/ /app/shared/

EXPOSE 5002

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "5002"]
