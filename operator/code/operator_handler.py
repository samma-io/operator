import kopf
import logging
from kubernetes.client.rest import ApiException
from kubernetes import client, config, watch
import yaml
import json 
from pprint import pprint


#Our code
from deployJob import deleteJob, deployJob
from deploycron import deleteCron, deployCron

# Import lissen for changes




try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper


config.load_incluster_config()
api = client.CoreV1Api()
batch1api = client.BatchV1Api()
k8sapi =client.CustomObjectsApi()



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
            logging.info("No configs ")
        return haveConfigmap

    #No confimag is there lets deploy it
    if isConfigMapDeploy('filebeat') == False:
        f = open("code/scanners/core/config-filebeat.yaml", "r")
        toDeploy = yaml.load(f, Loader=Loader)
        try:
            api_response = api.create_namespaced_config_map(namespace="samma-io",body=toDeploy)
            logging.info(api_response)
        except ApiException as e:
            logging.info("Exception when calling WellKnownApi->get_service_account_issuer_open_id_configuration: %s\n" % e)
    

    if isConfigMapDeploy('live') == False:
        f = open("code/scanners/core/config-live.yaml", "r")
        toDeploy = yaml.load(f, Loader=Loader)
        try:
            api_response = api.create_namespaced_config_map(namespace="samma-io",body=toDeploy)
            logging.info(api_response)
        except ApiException as e:
            logging.info("Exception when calling WellKnownApi->get_service_account_issuer_open_id_configuration: %s\n" % e)


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
    env_data = {}

    #Set to none we deploy job else we deploy crontab
    scheduler = "none"
    try:
        scanners  = body['spec']['scanners']
    except:
        scanners = ['nmap']



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
    try: 
        scheduler = body['spec']['scheduler']
    except:
        pass

    #Deploy the scanners
    for scanner in scanners:
        #What kind of jov do we want. Lets check if there is a scedule tag. 
        # If there is a schudel tag then deploy a cronjob ! 
        if scheduler != "none":
            deployCron(scanner,target,scheduler,env_data)
        else:
            #Nope no sceduler lets deploy this a job
            deployJob(scanner,target,env_data)



    logging.info("Setup samma scanners for {0} with scanners {1} named {2}".format(target,scanners,name))


@kopf.on.delete('samma.io', 'v1', 'scanner') 
def delete(body, **kwargs): 
    name = body['metadata']['name']
    target = body['spec']['target']
    try:
        scanners  = body['spec']['scanners']
    except:
        scanners = ['nmap']

    scheduler = "none"
    try: 
        scheduler = body['spec']['scheduler']
    except:
        pass    
    for scanner in scanners:
        try:
            if scheduler != "none":
                deleteCron(scanner,target)
            else:
                #Nope no sceduler lets delete a job
                deleteJob(scanner,target)
        except:
            logging.info("Got some error when deleteing")

        
    logging.info("Delete samma scanners named {0}".format(name))
    return {'message': "done"} 

###
###
# Here we are watching Ingress and create and delete ingress based on ingress values
###


@kopf.on.create('networking.k8s.io', 'v1', 'Ingress') 
def create_fn(body, spec, **kwargs): 
   
    deployScanner = False
    scannerData={
        "apiVersion": "samma.io/v1",
        "kind": "Scanner",
            "metadata": {
                 "name": "empty",
                 "namespace": "samma-io"
                },
            "spec": {}

    }
    #Extract the samma scanenr data
    for annotaions in body['metadata']['annotations']:
        if annotaions == 'samma-io.alpha.kubernetes.io/enable':
            deployScanner = True
        else:
            annontaion = annotaions.split('/')
            if annontaion[0] == 'samma-io.alpha.kubernetes.io':
                #Sometimes we want the data as arrays to change , values to arrays
                if annontaion[1] == "samma_io_tags" or annontaion[1] == "scanners":
                    scannerData["spec"][annontaion[1]] = body['metadata']['annotations'][annotaions].split(",")
                else:
                    scannerData["spec"][annontaion[1]] = body['metadata']['annotations'][annotaions]
    #Create and deploy new scanner
    if deployScanner:
        scanners = body['metadata']['annotations']['samma-io.alpha.kubernetes.io/scanners'].split(',')
        targets = body['spec']['rules']
        for scanner in scanners:
            for target in targets:
                scannerData['metadata']['name']="{0}-{1}".format(scanner,target['host'].replace('.','-'))
                scannerData['spec']['target']= target['host']
                group = 'samma.io' # str | The custom resource's group name
                version = 'v1' # str | The custom resource's version
                namespace = 'samma-io' # str | The custom resource's namespace
                plural = 'scanner' # str | The custom resource's plural name. For TPRs this would be lowercase plural kind.
                body = scannerData # object | The JSON schema of the Resource to create.
                try:
                    api_response = k8sapi.create_namespaced_custom_object(group, version, namespace, plural, body)
                    logging.info("Scanner with name  {0}-{1} has bean created ".format(scanner,target['host'].replace('.','-')) )
                except ApiException as e:
                    print("Exception when installing the scanner into the cluster: %s\n" % e)
                
                logging.debug(scannerData)








    logging.info("############################")
    logging.info(scannerData)


@kopf.on.delete('networking.k8s.io', 'v1', 'Ingress') 
def delete(body, **kwargs): 
    logging.info("Ingress")
    #Extract the samma scanenr data
    for annotaions in body['metadata']['annotations']:
        if annotaions == 'samma-io.alpha.kubernetes.io/enable':
            deployScanner = True
    #Create and deploy new scanner
    if deployScanner:
        scanners = body['metadata']['annotations']['samma-io.alpha.kubernetes.io/scanners'].split(',')
        targets = body['spec']['rules']
        for scanner in scanners:
            for target in targets:
                group = 'samma.io' # str | The custom resource's group name
                version = 'v1' # str | The custom resource's version
                namespace = 'samma-io' # str | The custom resource's namespace
                plural = 'scanner' # str | The custom resource's plural name. For TPRs this would be lowercase plural kind.
                name = "{0}-{1}".format(scanner,target['host'].replace('.','-'))
                try:
                    api_response = k8sapi.delete_namespaced_custom_object(group, version, namespace, plural, name)
                    print("Scanner with name has bean delete {0}".format(name))
                except ApiException as e:
                    print("Exception when listing scanners in the cluster: %s\n" % e)

