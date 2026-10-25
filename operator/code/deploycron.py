import os
import logging
import ipaddress
import re
from jinja2 import Template
from kubernetes import client, config, watch
from kubernetes.client.rest import ApiException
import yaml
import json


config.load_incluster_config()
cronApi = client.BatchV1Api()


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



def _template_name_suffix(template_text):
    '''
    Return the literal a template appends after {{ NAME }} in its metadata.name
    line. nikto.yaml and the detect scanners frame {{ NAME }} bare and get "",
    nmap's port.yaml frames it as "{{ NAME }}-port" and gets "-port". Reading
    the suffix from the templates keeps every computed name equal to the name
    the rendered YAML actually carries.
    '''
    match = re.search(r'^\s*name:\s*\{\{\s*NAME\s*\}\}(\S*)\s*$', template_text, re.MULTILINE)
    return match.group(1) if match else ""


def cron_name(scanner, id_key, template_name):
    '''
    Full metadata.name of the CronJob built from <scanner>'s <template_name>.yaml:
    "<scanner>-<sanitized id><template suffix>", truncated to the 63 characters
    Kubernetes allows. deployCron and deleteCron both go through this helper so
    create, the already-deployed check and delete agree on the name by
    construction.
    '''
    base = re.sub(r'[^a-z0-9-]', '-', str(id_key).lower())
    base = re.sub(r'-+', '-', base).strip('-')
    suffix = ""
    try:
        f = open("/code/scanners/{0}/cron/{1}.yaml".format(scanner, template_name), "r")
        suffix = _template_name_suffix(f.read())
        f.close()
    except:
        pass
    return "{0}-{1}{2}".format(scanner, base, suffix)[:63]



def deleteCron(scanner,target="samma.io",templates=None,samma_io_id=None):
    # Same keying as deployCron so delete matches create by construction;
    # Scanners without a samma_io_id (Ingress-created) keep the legacy names.
    id_key = str(samma_io_id) if samma_io_id else target.replace('.',"-")
    for filename in os.listdir("/code/scanners/{0}/cron/".format(scanner)):
        job= filename.split(".")
        if templates is not None and job[0] not in templates:
            continue
        name = cron_name(scanner, id_key, job[0])
        try:
            cronApi.delete_namespaced_cron_job(namespace="samma-io",name=name)
            logging.info("Delete samma scanner job {0}".format(name))
        except:
            print("error deleting")


def deployCron(scanner,target="samma.io",sceduler="15 0 * * * ",env_data={},templates=None,samma_io_id=None,owner=None):
    '''

    To deploy a job we go to the service folder.
    Loop over the files and apply the files one by one into the samma-io namespace.
    '''
    # The target ends up inside the rendered CronJob YAML, so it must be a plain
    # IP address or hostname. Anything else is refused before we render.
    if not is_valid_target(target):
        logging.error("Refusing to deploy cron for scanner {0}: invalid target, must be an IP address or RFC 1123 hostname".format(scanner))
        return
    # The schedule is rendered into spec.schedule, so it must be a plain
    # 5-field cron expression. Anything else is refused before we render.
    scheduler = (sceduler or "").strip()
    if not re.match(r'^[0-9*/,\-]+( [0-9*/,\-]+){4}$', scheduler):
        logging.error("Refusing to deploy cron for scanner {0}: invalid cron schedule".format(scanner))
        return
    targetName = target.replace('.',"-")
    # CronJobs are keyed by the tenant's samma_io_id so two tenants can scan the
    # same host without the second one's scans being skipped by name. Scanners
    # without an id (Ingress-created) fall back to the legacy target name.
    id_key = str(samma_io_id) if samma_io_id else targetName
    if os.path.isdir("/code/scanners/{0}/cron/".format(scanner)):
        for filename in os.listdir("/code/scanners/{0}/cron/".format(scanner)):
            template_name = filename.split(".")[0]
            if templates is not None and template_name not in templates:
                continue
            logging.debug(filename)
            name = cron_name(scanner, id_key, template_name)
            haveDeployd=False
            try:
                pods = cronApi.list_namespaced_cron_job("samma-io")
                for pod in pods.items:
                    logging.info("Looping over pods")
                    if pod.metadata.name == name:
                        haveDeployd= True
            except:
                logging.info("Error Cant find CronJob to deploy")

            if not haveDeployd:
                    logging.info("Deploying")
                    #Open the yaml file
                    f = open("/code/scanners/{0}/cron/{1}".format(scanner,filename), "r")
                    #Add values to
                    template_text = f.read()
                    t = Template(template_text)
                    # The template appends its own suffix after {{ NAME }}, so the
                    # render value is the cron name minus that suffix; the rendered
                    # metadata.name then equals cron_name() exactly.
                    suffix = _template_name_suffix(template_text)
                    moniker = name[:-len(suffix)] if suffix else name
                    SCANNERFirst="string"
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
                    toDeployYaml = t.render(NAME=scalar_for_template(template_text, 'NAME', moniker),TARGET=scalar_for_template(template_text, 'TARGET', target),SCHEDULER=scalar_for_template(template_text, 'SCHEDULER', scheduler),ENV=safe_env,SCANNERFirst=SCANNERFirst)
                    logging.debug(toDeployYaml)
                    #Make to json
                    toDeploy = yaml.safe_load(toDeployYaml)
                    if owner:
                        # The CronJob is garbage-collected together with its Scanner.
                        toDeploy['metadata']['ownerReferences'] = [{
                            'apiVersion': 'samma.io/v1',
                            'kind': 'Scanner',
                            'name': owner['name'],
                            'uid': owner['uid'],
                            'controller': True,
                        }]
                    try:
                        obj = cronApi.create_namespaced_cron_job("samma-io", toDeploy) 
                    except ApiException as e:
                        logging.info("Exception Cannot create cron job %s\n" % e)
    else:
        logging.info("The scanner {0} is not in our scanner repo ").format(scanner)    
