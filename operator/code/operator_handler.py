import kopf
import logging
from kubernetes import client, config, watch
import yaml
import json 

#Our code
from deployJob import deleteJob, deployJob
from deploycron import deleteCron, deployCron



try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper


config.load_incluster_config()
api = client.CoreV1Api()
batch1api = client.BatchV1Api()


def initOperator():
    '''
    Setup config files and other resources that ate need for the scanners.
    The deployemtn can be overwritten in the operator deploy by mounting other file into the continer
    '''
    def isConfigMapDeploy(name):
        #Return true om configen är deployad
        configmaps = api.list_namespaced_config_map("samma-io")
        haveConfigmap=False
        try:
            for map in configmaps.items:
                if map.metadata.name == name:
                    haveConfigmap= True
        except:
            print("No configs ")
        return haveConfigmap

    #No confimag is there lets deploy it
    if isConfigMapDeploy('filebeat') == False:
        f = open("code/scanners/core/config-filebeat.yaml", "r")
        toDeploy = yaml.load(f, Loader=Loader)
        obj = api.create_namespaced_config_map(namespace="samma-io",body=toDeploy) 

    if isConfigMapDeploy('live') == False:
        f = open("code/scanners/core/config-live.yaml", "r")
        toDeploy = yaml.load(f, Loader=Loader)
        obj = api.create_namespaced_config_map(namespace="samma-io",body=toDeploy) 


    #Lets install the filebeat config for us










##
#Init the initOperator
initOperator()


##Start lookin g for changes
@kopf.on.create('samma.io', 'v1', 'scanner') 
def create_fn(body, spec, **kwargs): 
    
    #Validate we have values
    name = body['metadata']['name']
    target = body['spec']['target']
    scanners  = body['spec']['scanners'] or ['nmap']
    env_data = {}

    try:
        env_data['samma_io_id'] = body['spec']['samma_io_id'] or "1234"
    except:
        pass
    try:
        env_data['samma_io_tags']=  body['spec']['samma_io_tags'] or ["scanner","nmap","samma"]
    except:
        pass
    try:
        env_data['samme_io_json']= body['spec']['samma_io_json'] or {"attacke":"true"}
    except:
        pass
    try:
        env_data['write_to_file']= body['spec']['write_to_file'] or  "true"
    except:
        pass
    try:
        env_data['elasticsearch']= body['spec']['elasticsearch'] or "elasticsearch"
    except:
        pass


    #Deploy the scanners
    for scanner in scanners:
        #What kind of jov do we want. Lets check if there is a scedule tag. 
        # If there is a schudel tag then deploy a cronjob ! 
        if body['spec']['scheduler']:
            deployCron(scanner,target,body['spec']['scheduler'])
        else:
            #Nope no sceduler lets deploy this a job
            deployJob(scanner,target)



    logging.info("Setup samma scanners for {0} with scanners {1} named {2}".format(target,scanners,name))


@kopf.on.delete('samma.io', 'v1', 'scanner') 
def delete(body, **kwargs): 
    name = body['metadata']['name']
    target = body['spec']['target']
    scanners  = body['spec']['scanners']
    for scanner in scanners:
        try:
            if body['spec']['scheduler']:
                deleteCron(scanner,target)
            else:
                #Nope no sceduler lets delete a job
                deleteJob(scanner,target)
        except:
            print("Got some error when deleteing")

        
    print("Delete samma scanners named {0}".format(name))
    return {'message': "done"} 



