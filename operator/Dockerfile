FROM python:3.7 
RUN pip install kopf && pip install kubernetes && pip install redis 
RUN pip install PyYAML
RUN pip install Jinja2
COPY /code /code/ 

RUN useradd -ms /bin/bash samma
RUN chown samma:samma /code/
RUN chmod 664 /code/*.py

USER samma


CMD kopf run --standalone /code/operator_handler.py --verbose