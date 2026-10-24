import os
import logging
import ipaddress
import re
from jinja2 import Template
from jinja2 import Environment
from kubernetes import client, config, watch
from kubernetes.client.rest import ApiException
import yaml
import json


config.load_incluster_config()
api = client.CoreV1Api()
batch1api = client.BatchV1Api()


def is_valid_target(value):
    """Only IP addresses (IPv4/IPv6) or RFC 1123 hostnames are valid targets."""
    if not isinstance(value, str):
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass
    if len(value) > 253:
        return False
    return all(
        re.match(r'^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$', label)
        for label in value.split('.')
    )


def scalar_for_template(template_text, var, value):
    '''
    Return the value to render a YAML scalar placeholder as one single scalar.

    When every {{ var }} occurrence in the template sits alone in the YAML value
    slot the fully JSON-quoted form is returned, so the value renders as exactly
    one double-quoted YAML scalar. When an occurrence is kept inside an already
    quoted or otherwise pre-framed position (e.g. "{{ TARGET }}" or
    --hostname-target={{ TARGET }}), wrapping it a second time would break
    yaml.safe_load, so only the JSON-escaped interior is returned there.
    '''
    full = json.dumps(value)
    for match in re.finditer(r'\{\{\s*' + var + r'\s*\}\}', template_text):
        before = template_text[:match.start()].rstrip()
        after = template_text[match.end():]
        if not (before.endswith(':') and (after == '' or after[0] in ' \t\r\n')):
            return full[1:-1]
    return full


def deleteJob(scanner,target="samma.io",templates=None):
    targetName = target.replace('.',"-")
    for filename in os.listdir("/code/scanners/{0}/job/".format(scanner)):
        job= filename.split(".")
        if templates is not None and job[0] not in templates:
            continue
        try:
            batch1api.delete_namespaced_job(namespace="samma-io",name="{0}-{1}-{2}".format(scanner,targetName,job[0]))
            logging.info("Delete samma scanner job {0}-{1}-{2}".format(scanner,targetName,job[0]))
        except:
            logging.info("ERROR samma scanner job {0}-{1}-{2}".format(scanner,targetName,job[0]))
def deployJob(scanner,target="samma.io",env_data={},templates=None):
    '''

    To deploy a job we go to the service folder.
    Loop over the files and apply the files one by one into the samma-io namespace.
    '''
    # The target ends up inside the rendered Job YAML, so it must be a plain
    # IP address or hostname. Anything else is refused before we render.
    if not is_valid_target(target):
        logging.error("Refusing to deploy scanner {0}: invalid target, must be an IP address or RFC 1123 hostname".format(scanner))
        return
    targetName = target.replace('.',"-")

    if os.path.isdir("/code/scanners/{0}/job/".format(scanner)):
        for filename in os.listdir("/code/scanners/{0}/job/".format(scanner)):
            template_name = filename.split(".")[0]
            if templates is not None and template_name not in templates:
                continue
            print(filename)
            haveDeployd=False
            pods = batch1api.list_namespaced_job("samma-io")
            for pod in pods.items:
                logging.info("Looping over pods")
                if pod.metadata.name == "{0}-{1}".format(scanner,targetName):
                    haveDeployd= True

            if not haveDeployd:
                    logging.info("Deploying Scanner")
                    #Open the yaml file
                    f = open("/code/scanners/{0}/job/{1}".format(scanner,filename), "r")
                    #Add values to
                    template_text = f.read()
                    t = Template(template_text)
                    SCANNERFirst="string"
                    logging.info(target[0])
                    try:
                        SCANNERFirst=int(target[0])
                        logging.info("########################")
                        logging.info(SCANNERFirst)
                    except ValueError:
                        logging.info("########################")
                        logging.info(SCANNERFirst)
                    # ENV values render inside quoted template placeholders, so pass
                    # the JSON-escaped interior; every env value stays one scalar.
                    safe_env = {k: json.dumps(str(v))[1:-1] for k, v in env_data.items()}
                    toDeployYaml = t.render(NAME=scalar_for_template(template_text, 'NAME', "{0}-{1}".format(scanner,targetName)),TARGET=scalar_for_template(template_text, 'TARGET', target),ENV=safe_env,SCANNERFirst=SCANNERFirst)
                    logging.debug(toDeployYaml)
                    #Make to json
                    toDeploy = yaml.safe_load(toDeployYaml)
                    try:
                        obj = batch1api.create_namespaced_job("samma-io", toDeploy) 
                    except ApiException as e:
                        logging.info("Exception cannot create job %s\n" % e)
    else:
        logging.info("The scanner {0} is not in our scanner repo ").format(scanner)
