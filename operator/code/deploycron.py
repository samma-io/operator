import os
import logging
from jinja2 import Template
from kubernetes import client, config, watch
from kubernetes.client.rest import ApiException
import yaml
import json 


try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper


config.load_incluster_config()
cronApi = client.BatchV1Api()



def deleteCron(scanner,target="samma.io",templates=None):
    targetName = target.replace('.',"-")
    for filename in os.listdir("/code/scanners/{0}/cron/".format(scanner)):
        job= filename.split(".")
        if templates is not None and job[0] not in templates:
            continue
        try:
            cronApi.delete_namespaced_cron_job(namespace="samma-io",name="{0}-{1}-{2}".format(scanner,targetName,job[0]))
            logging.info("Delete samma scanner job {0}".format(scanner))
        except:
            print("error deleting")


def deployCron(scanner,target="samma.io",sceduler="15 0 * * * ",env_data={},templates=None):
    '''

    To deploy a job we go to the service folder.
    Loop over the files and apply the files one by one into the samma-io namespace.
    '''
    targetName = target.replace('.',"-")
    if os.path.isdir("/code/scanners/{0}/cron/".format(scanner)):
        for filename in os.listdir("/code/scanners/{0}/cron/".format(scanner)):
            template_name = filename.split(".")[0]
            if templates is not None and template_name not in templates:
                continue
            logging.debug(filename)
            #Render first: the CronJob's real name lives in the rendered template.
            #Templates are inconsistent -- some are "{{ NAME }}", others append a
            #suffix ("{{ NAME }}-port") -- so it cannot be derived from the scanner
            #and target alone.
            f = open("/code/scanners/{0}/cron/{1}".format(scanner,filename), "r")
            t = Template(f.read())
            f.close()
            SCANNERFirst="string"
            try:
                SCANNERFirst=int(target[0])
            except ValueError:
                pass
            safe_env = {k: str(v).replace('"', '\\"') for k, v in env_data.items()}
            toDeployYaml = t.render(NAME="{0}-{1}".format(scanner,targetName),TARGET=target,SCHEDULER=sceduler,ENV=safe_env,SCANNERFirst=SCANNERFirst)
            logging.debug(toDeployYaml)
            toDeploy = yaml.load(toDeployYaml, Loader=Loader)

            cronName = toDeploy.get("metadata", {}).get("name")
            if cronName is None:
                logging.error("Template {0}/{1} has no metadata.name; skipping".format(scanner,filename))
                continue

            #Look the CronJob up by name rather than listing the namespace. The old
            #list_namespaced_cron_job() call pulled and deserialised every CronJob
            #on every pass; a read by name is O(1). The bare `except` around it also
            #swallowed real API errors and then fell through to create, producing 409s.
            haveDeployd = True
            try:
                cronApi.read_namespaced_cron_job(name=cronName, namespace="samma-io")
            except ApiException as e:
                if e.status != 404:
                    raise
                haveDeployd = False

            if not haveDeployd:
                    logging.info("Deploying CronJob {0}".format(cronName))
                    try:
                        obj = cronApi.create_namespaced_cron_job("samma-io", toDeploy) 
                    except ApiException as e:
                        logging.info("Exception Cannot create cron job %s\n" % e)
            else:
                    logging.debug("CronJob {0} already exists; nothing to do".format(cronName))
    else:
        logging.info("The scanner {0} is not in our scanner repo ").format(scanner)    
