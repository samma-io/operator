FROM python:3.7

#copy code
COPY code/ /app/code/
WORKDIR /app/code

#Install deps
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

RUN useradd -ms /bin/bash samma
RUN chown samma:samma /app/code/
RUN chmod 664 /app/code/*.py

USER samma

EXPOSE 80

# Start server
ENTRYPOINT [ "./entrypoint.sh" ] 
