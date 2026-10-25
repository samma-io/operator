FROM python:3.12-slim
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
COPY /code /code/

# uid 1000 by number: Kubernetes can only verify runAsNonRoot against a numeric
# user, and a chart or pod spec may name the uid without knowing this image.
RUN groupadd -g 1000 samma && useradd -m -u 1000 -g 1000 -s /bin/bash samma
RUN chown samma:samma /code/
RUN chmod 664 /code/*.py

USER 1000:1000


CMD kopf run --standalone /code/operator_handler.py --verbose
