import os
import logging
from jinja2 import Template
from jinja2 import Environment
from kubernetes import client, config, watch
from kubernetes.client.rest import ApiException
import yaml
import json 


try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper


config.load_incluster_config()
api = client.CoreV1Api()
batch1api = client.BatchV1Api()


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
    targetName = target.replace('.',"-")

    if os.path.isdir("/code/scanners/{0}/job/".format(scanner)):
        for filename in os.listdir("/code/scanners/{0}/job/".format(scanner)):
            template_name = filename.split(".")[0]
            if templates is not None and template_name not in templates:
                continue
            logging.debug(filename)
            #Render first: the Job's real name lives in the rendered template.
            #Templates are inconsistent -- some are "{{ NAME }}", others append a
            #suffix ("{{ NAME }}-port") -- so the name cannot be derived from the
            #scanner and target alone.
            f = open("/code/scanners/{0}/job/{1}".format(scanner,filename), "r")
            t = Template(f.read())
            f.close()
            SCANNERFirst="string"
            try:
                SCANNERFirst=int(target[0])
            except ValueError:
                pass
            safe_env = {k: str(v).replace('"', '\\"') for k, v in env_data.items()}
            toDeployYaml = t.render(NAME="{0}-{1}".format(scanner,targetName),TARGET=target,ENV=safe_env,SCANNERFirst=SCANNERFirst)
            logging.debug(toDeployYaml)
            toDeploy = yaml.load(toDeployYaml, Loader=Loader)

            jobName = toDeploy.get("metadata", {}).get("name")
            if jobName is None:
                logging.error("Template {0}/{1} has no metadata.name; skipping".format(scanner,filename))
                continue

            #Look the Job up by name. list_namespaced_job() used to be called here,
            #inside this loop: it pulls every Job in the namespace and deserialises
            #it, so memory grew with the number of accumulated Jobs until the pod
            #was OOMKilled. A read by name is O(1) and does not grow.
            haveDeployd = True
            try:
                batch1api.read_namespaced_job(name=jobName, namespace="samma-io")
            except ApiException as e:
                if e.status != 404:
                    raise
                haveDeployd = False

            if not haveDeployd:
                    logging.info("Deploying Scanner job {0}".format(jobName))
                    try:
                        obj = batch1api.create_namespaced_job("samma-io", toDeploy) 
                    except ApiException as e:
                        logging.info("Exception cannot create job %s\n" % e)
            else:
                    logging.debug("Job {0} already exists; nothing to do".format(jobName))
    else:
        logging.info("The scanner {0} is not in our scanner repo ").format(scanner)
