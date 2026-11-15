FROM python:3.12-slim
# Standard library only: no requirements to install.
COPY code/ /code/

# uid 1000 by number: Kubernetes can only verify runAsNonRoot against a numeric
# user, and a chart or pod spec may name the uid without knowing this image.
RUN groupadd -g 1000 samma && useradd -m -u 1000 -g 1000 -s /bin/bash samma && chown -R samma:samma /code
USER 1000:1000

ENV PYTHONUNBUFFERED=1
EXPOSE 9100
CMD ["python3", "/code/collector.py"]
