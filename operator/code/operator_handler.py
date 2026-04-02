import kopf
import logging
from kubernetes.client.rest import ApiException
from kubernetes import client, config, watch
import yaml
import json
from pprint import pprint
import os
import requests


#Our code
from deployJob import deleteJob, deployJob
from deploycron import deleteCron, deployCron
from profile_resolver import resolve_profiles, parse_scanner_spec

# Import lissen for changes
## Setup ENV 
samma_io_id = os.getenv('SAMMA_IO_ID' , '1234')
samma_io_tags = os.getenv('SAMMA_IO_TAGS' , ["samma"])
samma_io_json = os.getenv('SAMMA_IO_JSON' , '{"samma":"scanner"}')
samma_io_scanners = os.getenv('SAMMA_IO_SCANNER' , "nmap")
write_to_file = os.getenv('WRITE_TO_FILE' , 'true')
elasticsearch = os.getenv('ELASTICSEARCH' , 'true')
samma_io_api_url = os.getenv('SAMMA_IO_API_URL', 'https://www.samma.io')
samma_io_api_token = os.getenv('SAMMA_IO_API_TOKEN', '')
samma_io_profile_id = os.getenv('SAMMA_IO_PROFILE_ID', '')



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


    #Deploy default scanner-profiles ConfigMap
    if isConfigMapDeploy('scanner-profiles') == False:
        profiles_cm = client.V1ConfigMap(
            metadata=client.V1ObjectMeta(name="scanner-profiles", namespace="samma-io"),
            data={
                "default": "nmap,nikto",
                "web": "nikto,nmap/http",
                "network": "nmap/port,nmap/tls",
                "full": "nmap,nikto,tsunami,base",
            }
        )
        try:
            api_response = api.create_namespaced_config_map(namespace="samma-io", body=profiles_cm)
            logging.info("Created scanner-profiles ConfigMap")
        except ApiException as e:
            logging.info("Exception when creating scanner-profiles ConfigMap: %s\n" % e)

##
#Init the initOperator
initOperator()


def post_target_to_api(host):
    """POST a discovered domain to the external samma.io API if a token is configured."""
    if not samma_io_api_token:
        return
    url = "{0}/api/v1/targets".format(samma_io_api_url.rstrip('/'))
    payload = {
        "value": host,
        "type": "dns",
        "label": host,
    }
    if samma_io_profile_id:
        payload["profileId"] = samma_io_profile_id
    headers = {
        "Authorization": "Bearer {0}".format(samma_io_api_token),
        "Content-Type": "application/json",
    }
    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=10)
        logging.info("Posted target %s to API: %s", host, resp.status_code)
    except Exception as e:
        logging.warning("Failed to post target %s to API: %s", host, e)


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
        scanners = samma_io_scanners.split(',')
        print("#################")
        print(scanners)

    try:
        env_data['samma_io_id'] = body['spec']['samma_io_id'] or samma_io_id
    except:
        pass
    try:
        env_data['samma_io_tags']=  body['spec']['samma_io_tags'] or samma_io_tags
    except:
        pass
    try:
        env_data['samme_io_json']= body['spec']['samma_io_json'] or samma_io_json
    except:
        pass
    try:
        env_data['write_to_file']= body['spec']['write_to_file'] or  write_to_file
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

    templates = body['spec'].get('templates', None)

    #Deploy the scanners
    for scanner in scanners:
        #What kind of jov do we want. Lets check if there is a scedule tag.
        # If there is a schudel tag then deploy a cronjob !
        if scheduler != "none":
            deployCron(scanner,target,scheduler,env_data,templates=templates)
        else:
            #Nope no sceduler lets deploy this a job
            deployJob(scanner,target,env_data,templates=templates)



    logging.info("Setup samma scanners for {0} with scanners {1} named {2}".format(target,scanners,name))


@kopf.on.delete('samma.io', 'v1', 'scanner') 
def delete(body, **kwargs): 
    name = body['metadata']['name']
    target = body['spec']['target']
    try:
        scanners  = body['spec']['scanners']
    except:
        scanners = samma_io_scanners.split(',')

    scheduler = "none"
    try:
        scheduler = body['spec']['scheduler']
    except:
        pass
    templates = body['spec'].get('templates', None)
    for scanner in scanners:
        try:
            if scheduler != "none":
                deleteCron(scanner,target,templates=templates)
            else:
                #Nope no sceduler lets delete a job
                deleteJob(scanner,target,templates=templates)
        except:
            logging.info("Got some error when deleteing")

        
    logging.info("Delete samma scanners named {0}".format(name))
    return {'message': "done"} 

###
###
# Here we are watching Ingress and create and delete ingress based on ingress values
###


@kopf.on.create('networking.k8s.io', 'v1', 'Ingress')
def ingress_create_fn(body, spec, **kwargs):

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
    annotations = body['metadata'].get('annotations', {})

    #Extract the samma scanner data
    for ann_key in annotations:
        if ann_key == 'samma-io.alpha.kubernetes.io/enable':
            deployScanner = True
        else:
            ann_parts = ann_key.split('/')
            if ann_parts[0] == 'samma-io.alpha.kubernetes.io':
                field = ann_parts[1]
                # Skip profile and scanners - handled separately below
                if field in ('profile', 'scanners'):
                    continue
                if field == "samma_io_tags":
                    scannerData["spec"][field] = annotations[ann_key].split(",")
                else:
                    scannerData["spec"][field] = annotations[ann_key]

    #Create and deploy new scanner
    if deployScanner:
        # Resolve scanner specs from profile, scanners annotation, or default profile
        profile_ann = annotations.get('samma-io.alpha.kubernetes.io/profile')
        scanners_ann = annotations.get('samma-io.alpha.kubernetes.io/scanners')

        if profile_ann:
            profile_names = [p.strip() for p in profile_ann.split(',')]
            scanner_specs = resolve_profiles(profile_names, api)
        elif scanners_ann:
            scanner_specs = [(s.strip(), None) for s in scanners_ann.split(',')]
        else:
            scanner_specs = resolve_profiles(['default'], api)

        if not scanner_specs:
            logging.warning("No scanner specs resolved for Ingress, falling back to env default")
            scanner_specs = [(s.strip(), None) for s in samma_io_scanners.split(',')]

        targets = body['spec']['rules']
        for scanner, template in scanner_specs:
            for target in targets:
                host = target['host']
                post_target_to_api(host)
                host_sanitized = host.replace('.', '-')
                if template:
                    resource_name = "{0}-{1}-{2}".format(scanner, host_sanitized, template)
                else:
                    resource_name = "{0}-{1}".format(scanner, host_sanitized)

                scanner_body = dict(scannerData)
                scanner_body['metadata'] = dict(scannerData['metadata'])
                scanner_body['spec'] = dict(scannerData['spec'])
                scanner_body['metadata']['name'] = resource_name
                scanner_body['spec']['target'] = host
                scanner_body['spec']['scanners'] = [scanner]
                if template:
                    scanner_body['spec']['templates'] = [template]

                group = 'samma.io'
                version = 'v1'
                namespace = 'samma-io'
                plural = 'scanner'
                try:
                    api_response = k8sapi.create_namespaced_custom_object(group, version, namespace, plural, scanner_body)
                    logging.info("Scanner with name %s has been created", resource_name)
                except ApiException as e:
                    print("Exception when installing the scanner into the cluster: %s\n" % e)

                logging.debug(scanner_body)





    logging.info("############################")
    logging.info(scannerData)


@kopf.on.delete('networking.k8s.io', 'v1', 'Ingress')
def ingress_delete(body, **kwargs):
    logging.info("Ingress delete")
    annotations = body['metadata'].get('annotations', {})
    deployScanner = False
    for ann_key in annotations:
        if ann_key == 'samma-io.alpha.kubernetes.io/enable':
            deployScanner = True

    if deployScanner:
        # Resolve scanner specs using same logic as create
        profile_ann = annotations.get('samma-io.alpha.kubernetes.io/profile')
        scanners_ann = annotations.get('samma-io.alpha.kubernetes.io/scanners')

        if profile_ann:
            profile_names = [p.strip() for p in profile_ann.split(',')]
            scanner_specs = resolve_profiles(profile_names, api)
        elif scanners_ann:
            scanner_specs = [(s.strip(), None) for s in scanners_ann.split(',')]
        else:
            scanner_specs = resolve_profiles(['default'], api)

        if not scanner_specs:
            scanner_specs = [(s.strip(), None) for s in samma_io_scanners.split(',')]

        targets = body['spec']['rules']
        for scanner, template in scanner_specs:
            for target in targets:
                host_sanitized = target['host'].replace('.', '-')
                if template:
                    name = "{0}-{1}-{2}".format(scanner, host_sanitized, template)
                else:
                    name = "{0}-{1}".format(scanner, host_sanitized)

                group = 'samma.io'
                version = 'v1'
                namespace = 'samma-io'
                plural = 'scanner'
                try:
                    api_response = k8sapi.delete_namespaced_custom_object(group, version, namespace, plural, name)
                    print("Scanner with name has been deleted: {0}".format(name))
                except ApiException as e:
                    print("Exception when deleting scanner from cluster: %s\n" % e)

