import os
import logging
from jinja2 import Template
from kubernetes import client, config, watch
import yaml
import json 


try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper


config.load_incluster_config()
#api = client.CoreV1Api()
#cronApi = client.BatchV1Api()
cronApi = client.BatchV1beta1Api()



def deleteCron(scanner,target="samma.io"):
    targetName = target.replace('.',"-")
    for filename in os.listdir("/code/scanners/{0}/cron/".format(scanner)):
        job= filename.split(".")
        try:
            cronApi.delete_namespaced_cron_job(namespace="samma-io",name="{0}-{1}-{2}".format(scanner,targetName,job[0]))
            print("Delete samma scanner job {0}".format(scanner))
        except:
            print("error deleting")


def deployCron(scanner,target="samma.io",sceduler="15 0 * * * "):
    '''

    To deploy a job we go to the service folder.
    Loop over the files and apply the files one by one into the samma-io namespace.
    '''
    targetName = target.replace('.',"-")

    for filename in os.listdir("/code/scanners/{0}/cron/".format(scanner)):
        print("##############################")
        print(filename)
        haveDeployd=False
        try:
            pods = cronApi.list_namespaced_cron_job("samma-io")
            for pod in pods.items:
                logging.info("Looping over pods")
                if pod.metadata.name == "{0}-{1}".format(scanner,targetName):
                    haveDeployd= True
        except:
            print("No cronjobs is here")

        if not haveDeployd:
                logging.info("############# deploying")
                #Open the yaml file
                
                f = open("/code/scanners/{0}/cron/{1}".format(scanner,filename), "r")
                #Add values to 
                t = Template(f.read())
                toDeployYaml = t.render(NAME="{0}-{1}".format(scanner,targetName),TARGET=target,SCHEDULER=sceduler)
                print(toDeployYaml)
                #Make to json
                toDeploy = yaml.load(toDeployYaml, Loader=Loader)
                obj = cronApi.create_namespaced_cron_job("samma-io", toDeploy) 

