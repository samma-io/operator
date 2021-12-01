FROM python:3.7 
RUN pip install kopf && pip install kubernetes && pip install redis 
RUN pip install PyYAML
RUN pip install Jinja2
COPY /code /code/ 
CMD kopf run --standalone /code/operator_handler.py --verbose