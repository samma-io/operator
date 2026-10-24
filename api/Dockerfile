FROM python:3.12-slim

#copy code
COPY code/ /app/code/
WORKDIR /app/code

#Install deps
RUN pip install --no-cache-dir --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# uid 1000 by number: Kubernetes can only verify runAsNonRoot against a numeric
# user, and a chart or pod spec may name the uid without knowing this image.
RUN groupadd -g 1000 samma && useradd -m -u 1000 -g 1000 -s /bin/bash samma
RUN chown samma:samma /app/code/
RUN chmod 664 /app/code/*.py

USER 1000:1000

EXPOSE 80

# Start server
ENTRYPOINT [ "./entrypoint.sh" ]
