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
cronApi = client.BatchV1beta1Api()



def deleteCron(scanner,target="samma.io"):
    targetName = target.replace('.',"-")
    for filename in os.listdir("/code/scanners/{0}/cron/".format(scanner)):
        job= filename.split(".")
        try:
            cronApi.delete_namespaced_cron_job(namespace="samma-io",name="{0}-{1}-{2}".format(scanner,targetName,job[0]))
            logging.info("Delete samma scanner job {0}".format(scanner))
        except:
            print("error deleting")


def deployCron(scanner,target="samma.io",sceduler="15 0 * * * ",env_data={}):
    '''

    To deploy a job we go to the service folder.
    Loop over the files and apply the files one by one into the samma-io namespace.
    '''
    targetName = target.replace('.',"-")
    if os.path.isdir("/code/scanners/{0}/cron/".format(scanner)):
        for filename in os.listdir("/code/scanners/{0}/cron/".format(scanner)):
            logging.debug(filename)
            haveDeployd=False
            try:
                pods = cronApi.list_namespaced_cron_job("samma-io")
                for pod in pods.items:
                    logging.info("Looping over pods")
                    if pod.metadata.name == "{0}-{1}".format(scanner,targetName):
                        haveDeployd= True
            except:
                logging.info("Error Cant find CronJob to deploy")

            if not haveDeployd:
                    logging.info("Deploying")
                    #Open the yaml file

                    f = open("/code/scanners/{0}/cron/{1}".format(scanner,filename), "r")
                    #Add values to 
                    t = Template(f.read())
                    try:
                        SCANNERFirst=int(target[0])
                        logging.info("########################")
                        logging.info(SCANNERFirst)
                    except ValueError:
                        logging.info("########################")
                        logging.info(SCANNERFirst)
                    toDeployYaml = t.render(NAME="{0}-{1}".format(scanner,targetName),TARGET=target,SCHEDULER=sceduler,ENV=env_data,SCANNERFirst=SCANNERFirst)
                    logging.debug(toDeployYaml)
                    #Make to json
                    toDeploy = yaml.load(toDeployYaml, Loader=Loader)
                    try:
                        obj = cronApi.create_namespaced_cron_job("samma-io", toDeploy) 
                    except ApiException as e:
                        logging.info("Exception Cannot create cron job %s\n" % e)
    else:
        logging.info("The scanner {0} is not in our scanner repo ").format(scanner)    
