import kopf
import logging
from kubernetes import client, config, watch
import yaml
import json 
from jinja2 import Template

try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper


config.load_incluster_config()
api = client.CoreV1Api()
batch1api = client.BatchV1Api()



def delete(scanner,type="job",target="samma.io"):
    targetName = target.replace('.',"-")
    batch1api.delete_namespaced_job(namespace="samma-io",name="{0}-{1}".format(scanner,targetName))
    print("Delete samma scanner job {0}".format(scanner))

def deploy(scanner,envData,type="job",target="samma.io"):
    '''
    Deploy the service
    '''
    #Values we use
    targetName = target.replace('.',"-")


    #Open the jinja file
    f = open("code/scanners/{0}/{1}.jinja".format(scanner,type), "r")
    #Add values to 
    t = Template(f.read())
    toDeployYaml = t.render(NAME="{0}-{1}".format(scanner,targetName),TARGET=target,ENV=envData)

    #Make to json
    print("##################")
    print(toDeployYaml)
    toDeploy = yaml.load(toDeployYaml, Loader=Loader)

    logging.info(toDeploy)
    haveDeployd=False
    pods = batch1api.list_namespaced_job("samma-io")
    for pod in pods.items:
        logging.info("Looping over pods")
        if pod.metadata.name == "{0}-{1}".format(scanner,targetName):
            haveDeployd= True

    if not haveDeployd:
            logging.info("############# deploying")
            obj = batch1api.create_namespaced_job("samma-io", toDeploy) 





@kopf.on.create('samma.io', 'v1', 'scanner') 
def create_fn(body, spec, **kwargs): 
    
    #Validate we have values
    name = body['metadata']['name']
    target = body['spec']['target']
    scanners  = body['spec']['scanners'] or ['nmap']
    env = {
        "samma_io_id": body['spec']['samma_io_id'] or "1234",
        "samma_io_tags": body['spec']['samma_io_tags'] or ["scanner","nmap","samma"],
        "samme_io_json": body['spec']['samma_io_json'] or {"attacke":"true"},
        "write_to_file": body['spec']['write_to_file'] or  "true",
        "elasticsearch": body['spec']['elasticsearch'] or "elasticsearch"
    }


    #Deploy the scanners
    for scanner in scanners:
        deploy(scanner,env,"job",target)



    logging.info("Setup samma scanners for {0} with scanners {1} named {2}".format(target,scanners,name))


@kopf.on.delete('samma.io', 'v1', 'scanner') 
def delete(body, **kwargs): 
    name = body['metadata']['name']
    target = body['spec']['target']
    scanners  = body['spec']['scanners']
    for scanner in scanners:
        delete(scanner,"job",target)
    print("Delete samma scanners named {0}".format(name))
    return {'message': "done"} 



