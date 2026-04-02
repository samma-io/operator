FROM python:3.12-slim
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
COPY /code /code/

RUN useradd -ms /bin/bash samma
RUN chown samma:samma /code/
RUN chmod 664 /code/*.py

USER samma


CMD kopf run --standalone /code/operator_handler.py --verbose
