FROM python:3.12-slim
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
COPY code/ /code/

RUN useradd -ms /bin/bash samma && chown -R samma:samma /code
USER samma

EXPOSE 9100
CMD ["python3", "/code/bridge.py"]
