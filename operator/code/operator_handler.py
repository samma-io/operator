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
import target_policy

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
nats_url     = os.getenv('NATS_URL', 'nats://nats:4222')
nats_enabled = os.getenv('NATS_ENABLED', 'True')
nats_subject = os.getenv('NATS_SUBJECT', 'samma-io.scan')
default_weekly_schedule = os.getenv('SAMMA_IO_WEEKLY_SCHEDULE', '0 0 * * 0')

# A target that does not resolve is checked again every 5 minutes this many
# times before the operator gives up on it (DNS is often created after the
# Ingress, for example by external-dns).
MAX_RESOLVE_RETRIES = 12



try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper


config.load_incluster_config()
api = client.CoreV1Api()
batch1api = client.BatchV1Api()
k8sapi =client.CustomObjectsApi()
networking_api = client.NetworkingV1Api()



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
                "default": "http-headers-scanner,http-redirect-scanner,tls-scanner,nikto,nmap/http,port-scanner,traceroute-scanner,ssh-banner-scanner,nmap/port,nmap/tls,dns-scanner,whois-scanner",
                "web":     "http-headers-scanner,http-redirect-scanner,tls-scanner,nikto,nmap/http",
                "network": "port-scanner,traceroute-scanner,ssh-banner-scanner,nmap/port,nmap/tls",
                "dns":     "dns-scanner,whois-scanner",
                "detect":  "port-scanner,dns-scanner,http-headers-scanner,tls-scanner,traceroute-scanner,ssh-banner-scanner,whois-scanner,http-redirect-scanner",
                "classic": "nikto,nmap/port,nmap/http,nmap/tls,tsunami",
                "all":     "http-headers-scanner,http-redirect-scanner,tls-scanner,nikto,nmap/http,port-scanner,traceroute-scanner,ssh-banner-scanner,nmap/port,nmap/tls,dns-scanner,whois-scanner,tsunami",
                "full":    "nmap,nikto,tsunami,base",
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
def create_fn(body, spec, retry, **kwargs): 
    
    #Validate we have values
    name = body['metadata']['name']
    target = body['spec'].get('target')
    env_data = {}

    # Refuse the Scanner before anything is created when the target is not a
    # plain hostname or IP address, is not served by an Ingress (when
    # SAMMA_ALLOW_UNMANAGED_TARGETS is false) or resolves to a private address
    # (unless SAMMA_ALLOW_PRIVATE_TARGETS is true). See target_policy.py.
    try:
        target_policy.check_target(target, networking_api=networking_api)
    except target_policy.TargetUnresolvable as e:
        if retry >= MAX_RESOLVE_RETRIES:
            kopf.warn(body, reason='TargetRejected',
                      message="{0}; giving up after {1} attempts".format(e, retry + 1))
            raise kopf.PermanentError(str(e))
        kopf.warn(body, reason='TargetUnresolvable', message=str(e))
        raise kopf.TemporaryError("{0}; retrying in 5 minutes".format(e), delay=300)
    except target_policy.TargetRejected as e:
        kopf.warn(body, reason='TargetRejected', message=str(e))
        raise kopf.PermanentError(str(e))

    #Set to none we deploy job else we deploy crontab
    scheduler = "none"
    try:
        scanners  = body['spec']['scanners']
    except:
        scanners = samma_io_scanners.split(',')
        print("#################")
        print(scanners)

    try:
        env_data['SAMMA_IO_ID'] = body['spec']['samma_io_id'] or samma_io_id
    except:
        pass
    try:
        env_data['SAMMA_IO_TAGS'] = body['spec']['samma_io_tags'] or samma_io_tags
    except:
        pass
    try:
        env_data['SAMMA_IO_JSON'] = body['spec']['samma_io_json'] or samma_io_json
    except:
        pass
    try:
        env_data['WRITE_TO_FILE'] = body['spec']['write_to_file'] or write_to_file
    except:
        pass
    try:
        env_data['ELASTICSEARCH'] = body['spec']['elasticsearch'] or "elasticsearch"
    except:
        pass
    try:
        scheduler = body['spec']['scheduler']
    except:
        pass

    templates = body['spec'].get('templates', None)

    # Scanner names become template directory paths and the schedule is
    # rendered into CronJob YAML, so both are checked with the same patterns
    # the CRD schema carries.
    try:
        for scanner in scanners:
            target_policy.validate_scanner_name(scanner)
        target_policy.validate_schedule(scheduler)
    except target_policy.TargetRejected as e:
        kopf.warn(body, reason='ScannerRejected', message=str(e))
        raise kopf.PermanentError(str(e))

    env_data['NATS_URL']     = nats_url
    env_data['NATS_ENABLED'] = nats_enabled
    env_data['NATS_SUBJECT'] = nats_subject

    #Deploy the scanners — always run an immediate Job and a weekly CronJob.
    #Jobs/CronJobs are keyed by the tenant's samma_io_id and carry an owner
    #reference so Kubernetes removes them together with the Scanner CR.
    scanner_id = spec.get('samma_io_id')
    owner = {'name': name, 'uid': body['metadata'].get('uid')}
    cron_schedule = scheduler if scheduler != "none" else default_weekly_schedule
    for scanner in scanners:
        deployJob(scanner, target, env_data, templates=templates, samma_io_id=scanner_id, owner=owner)
        deployCron(scanner, target, cron_schedule, env_data, templates=templates, samma_io_id=scanner_id, owner=owner)



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
    scanner_id = body['spec'].get('samma_io_id')
    for scanner in scanners:
        try:
            deleteJob(scanner, target, templates=templates, samma_io_id=scanner_id)
            deleteCron(scanner, target, templates=templates, samma_io_id=scanner_id)
        except:
            logging.info("Got some error when deleteing")

        
    logging.info("Delete samma scanners named {0}".format(name))
    return {'message': "done"} 

###
###
# Here we are watching Ingress and create and delete ingress based on ingress values
###


@kopf.on.create('networking.k8s.io', 'v1', 'Ingress')
def ingress_create_fn(body, spec, retry, **kwargs):

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

        # Check every host once before any Scanner is created. Wildcard hosts
        # are skipped, hosts that fail the target policy get an event on the
        # Ingress, and hosts that do not resolve yet are retried later.
        hosts = []
        deferred = []
        for rule in body['spec'].get('rules') or []:
            host = rule.get('host')
            if not host:
                logging.info("Ingress rule without a host, nothing to scan")
                continue
            if target_policy.is_wildcard_host(host):
                logging.info("Skipping wildcard Ingress host %s: scanners need a concrete hostname", host)
                kopf.info(body, reason='WildcardHostSkipped',
                          message="Skipped wildcard host {0}: scanners need a concrete hostname".format(host))
                continue
            try:
                # This Ingress serves the host, so the managed check is not
                # needed; the apiserver already checked the host's syntax.
                target_policy.check_target(host, allow_unmanaged=True)
            except target_policy.TargetUnresolvable as e:
                logging.warning("%s", e)
                deferred.append(host)
                continue
            except target_policy.TargetRejected as e:
                logging.warning("%s", e)
                kopf.warn(body, reason='TargetRejected', message=str(e))
                continue
            hosts.append(host)

        posted = set()
        for scanner, template in scanner_specs:
            for host in hosts:
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
                    if host not in posted:
                        posted.add(host)
                        post_target_to_api(host)
                except ApiException as e:
                    if getattr(e, 'status', None) == 409:
                        logging.info("Scanner with name %s already exists", resource_name)
                    else:
                        print("Exception when installing the scanner into the cluster: %s\n" % e)
                        kopf.warn(body, reason='ScannerCreateFailed',
                                  message="Could not create Scanner {0}: {1}".format(resource_name, getattr(e, 'reason', e)))

                logging.debug(scanner_body)

        if deferred:
            message = "Ingress hosts {0} did not resolve yet".format(", ".join(deferred))
            if retry >= MAX_RESOLVE_RETRIES:
                kopf.warn(body, reason='TargetUnresolvable',
                          message="{0}; giving up after {1} attempts".format(message, retry + 1))
            else:
                raise kopf.TemporaryError("{0}; retrying in 5 minutes".format(message), delay=300)





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

        hosts = [rule.get('host') for rule in body['spec'].get('rules') or []]
        hosts = [host for host in hosts if host and not target_policy.is_wildcard_host(host)]
        for scanner, template in scanner_specs:
            for host in hosts:
                host_sanitized = host.replace('.', '-')
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

