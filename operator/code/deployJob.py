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
api = client.CoreV1Api()
batch1api = client.BatchV1Api()


def deleteJob(scanner,target="samma.io"):
    targetName = target.replace('.',"-")
    for filename in os.listdir("/code/scanners/{0}/job/".format(scanner)):
        job= filename.split(".")
        try:
            batch1api.delete_namespaced_job(namespace="samma-io",name="{0}-{1}-{2}".format(scanner,targetName,job[0]))
            logging.info("Delete samma scanner job {0}-{1}-{2}".format(scanner,targetName,job[0]))
        except:
            logging.info("ERROR samma scanner job {0}-{1}-{2}".format(scanner,targetName,job[0]))
def deployJob(scanner,target="samma.io",env_data={}):
    '''

    To deploy a job we go to the service folder.
    Loop over the files and apply the files one by one into the samma-io namespace.
    '''
    targetName = target.replace('.',"-")

    if os.path.isdir("/code/scanners/{0}/job/".format(scanner)):
        for filename in os.listdir("/code/scanners/{0}/job/".format(scanner)):
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
                    t = Template(f.read())
                    toDeployYaml = t.render(NAME="{0}-{1}".format(scanner,targetName),TARGET=target,ENV=env_data)
                    logging.debug(toDeployYaml)
                    #Make to json
                    toDeploy = yaml.load(toDeployYaml, Loader=Loader)
                    try:
                        obj = batch1api.create_namespaced_job("samma-io", toDeploy) 
                    except ApiException as e:
                        logging.info("Exception cannot create job %s\n" % e)
    else:
        logging.info("The scanner {0} is not in our scanner repo ").format(scanner)
