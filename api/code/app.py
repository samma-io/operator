from flask import Flask, render_template, request
import hmac
import ipaddress
import re
import yaml
import json
import logging
import os
import requests as http_requests
from kubernetes.client.rest import ApiException
from kubernetes import client, config, watch
from prometheus_flask_exporter import PrometheusMetrics
from profile_resolver import resolve_profiles



try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

# Load the kubernetes access
config.load_incluster_config()
k8sapi = client.CustomObjectsApi()
core_v1_api = client.CoreV1Api()

# The namespace the operator and the Scanners live in. The chart sets
# SAMMA_NAMESPACE from the pod's own namespace.
_GROUP, _VERSION, _NS, _PLURAL = 'samma.io', 'v1', os.getenv('SAMMA_NAMESPACE', 'samma-io'), 'scanner'


def sanitize_name(value):
    name = value.lower()
    name = re.sub(r'[^a-z0-9-]', '-', name)
    name = re.sub(r'-+', '-', name).strip('-')
    return name


def make_crd_name(scanner, target_id, template=None):
    """Scanner CRs are keyed by the tenant's samma_io_id, not the hostname, so
    two tenants registering the same host get their own scanners."""
    parts = [scanner, sanitize_name(str(target_id))]
    if template:
        parts.append(template)
    return '-'.join(parts)[:63]


def is_valid_target(value):
    """Only IP addresses (IPv4/IPv6) or RFC 1123 hostnames are valid targets."""
    if not isinstance(value, str):
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass
    if len(value) > 253:
        return False
    return all(
        re.match(r'^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$', label)
        for label in value.split('.')
    )

## Setup the flask app
app = Flask(__name__)
metrics = PrometheusMetrics(app)


## Setup ENV
samma_io_id = os.getenv('SAMMA_IO_ID' , '1234')
samma_io_tags = os.getenv('SAMMA_IO_TAGS' , ["samma"])
samma_io_json = os.getenv('SAMMA_IO_JSON' , "{'samma':'scanner'}")
samma_io_scanners = os.getenv('SAMMA_IO_SCANNER' , ["nmap","nikto","tsunami"])
write_to_file = os.getenv('WRITE_TO_FILE' , 'true')
elasticsearch = os.getenv('ELASTICSEARCH' , 'true')
samma_io_api_url = os.getenv('SAMMA_IO_API_URL', '')
samma_io_api_token = os.getenv('SAMMA_IO_API_TOKEN', '')
samma_io_profile_id = os.getenv('SAMMA_IO_PROFILE_ID', '')
samma_api_token = os.getenv('SAMMA_API_TOKEN', '')
if not samma_api_token:
    raise SystemExit('SAMMA_API_TOKEN is required: every API route needs an inbound bearer token, refusing to start without it')

_exempt_paths = frozenset(('/health', '/ready', '/metrics'))


@app.before_request
def require_bearer_token():
    if request.path in _exempt_paths:
        return
    header = request.headers.get('Authorization', '')
    if not header.startswith('Bearer '):
        return {'error': 'unauthorized'}, 401
    candidate = header[len('Bearer '):]
    if not hmac.compare_digest(candidate.encode(), samma_api_token.encode()):
        return {'error': 'unauthorized'}, 401


def post_target_to_api(target, target_id):
    """POST a target to the external samma.io API for validation if a token is configured."""
    if not samma_io_api_token:
        return
    url = "{0}/api/v1/targets".format(samma_io_api_url.rstrip('/'))
    payload = {
        "value": target,
        "type": "dns",
        "label": target,
        "targetId": target_id,
    }
    if samma_io_profile_id:
        payload["profileId"] = samma_io_profile_id
    headers = {
        "Authorization": "Bearer {0}".format(samma_io_api_token),
        "Content-Type": "application/json",
    }
    try:
        resp = http_requests.post(url, json=payload, headers=headers, timeout=10)
        logging.info("Posted target %s to API: %s", target, resp.status_code)
        return resp.status_code
    except Exception as e:
        logging.warning("Failed to post target %s to API: %s", target, e)
        return None


#
#
# Making a webbpage to show scanners 
#

@app.route('/')
def hello_world():
    # Get all scanner from the operator namespace
    returnThis={}
    group = 'samma.io' # str | The custom resource's group name
    version = 'v1' # str | The custom resource's version
    namespace = _NS # str | The custom resource's namespace
    plural = 'scanner' # str | The custom resource's plural name. For TPRs this would be lowercase plural kind.

    try:
        api_response = k8sapi.list_namespaced_custom_object(group, version, namespace, plural)
        returnThis=api_response
        
    except ApiException as e:
        print("Exception when listing scanners in the cluster: %s\n" % e)
    return render_template('base.html', SCANNERS=returnThis['items'])


@app.route('/scanner', methods=['PUT'])
def create_scanners():
    print("Trying to add scanner")
    if request.is_json:
        content = request.get_json()
        
        # Lets verify the data that we got
        try:  
            if content['target'] != "" or content['target'] != "empty":
                target = content['target']
                
            else:
                target="test.samma.io"

            try: 
                gotscanners = content['samma_io_scanners'].split(',')
                if "empty" in gotscanners:
                    scanners = samma_io_scanners
                else:
                    scanners = gotscanners
            except:
                scanners = samma_io_scanners

            try:
                gottags = content['samma_io_tags'].split(',')
                if "empty" in gottags:
                    samma_io_tags = os.getenv('SAMMA_IO_TAGS' , ["samma"])
                else:
                   samma_io_tags = gottags
            except:
                print("usingd efulats")

            try:
                if content['samma_io_id'] == "empty":
                    print("using defualt samma_io_id")
                    samma_io_id = os.getenv('SAMMA_IO_ID' , '1234')

                    
            except:
                    samma_io_id = content['samma_io_id']

            try:
                if content['samma_io_json'] == "empty":
                    print("using defualt samma_io_json")
                    samma_io_json = os.getenv('SAMMA_IO_JSON' , "{'samma':'scanner'}") 

            except:
                samma_io_json = content['samma_io_json']

            try:
                if content['write_to_file'] != "" or content['write_to_file'] != "empty":
                    write_to_file = content['write_to_file']
            except:
                print("using defualt write_to_file")
            try:
                if content['elasticsearch'] != "" or content['elasticsearch'] != "empty":
                    elastcisearch = content['elasticsearch']
            except:
                print("using default elasticsearch")
        except:
            print("We got some bad data {0}".format(content))
            return('{0}'.format(content))

        # For every scanner in json lets create scanners        
        scannerJSON = {
            "apiVersion": "samma.io/v1",
            "kind": "Scanner",
            "metadata": {
                "name": "{0}".format(target.replace('.','-')),
                "namespace": _NS
            },
            "spec": {
                "target": "{0}".format(target),
                "samma_io_id": "{0}".format(samma_io_id),
                "samma_io_tags": samma_io_tags,
                "samma_io_id": samma_io_id,
                "samma_io_json": samma_io_json,
                "write_to_file": "{0}".format(write_to_file),
                "elasticsearch": "{0}".format(elastcisearch),
                "scanners":scanners,
            }
            }
        toDeploy = yaml.dump(json.dumps(scannerJSON))
        # Add the scanner to the cluster as a CDR that the operator can read
        group = 'samma.io' # str | The custom resource's group name
        version = 'v1' # str | The custom resource's version
        namespace = _NS # str | The custom resource's namespace
        plural = 'scanner' # str | The custom resource's plural name. For TPRs this would be lowercase plural kind.
        body = scannerJSON # object | The JSON schema of the Resource to create.
        try:
            api_response = k8sapi.create_namespaced_custom_object(group, version, namespace, plural, body)
            print("Scanner with name  {0} has bean created".format(target.replace('.','-')))
        except ApiException as e:
            print("Exception when installing the scanner into the cluster: %s\n" % e)
        #print(toDeploy) 



        return 'JSON posted'
    else:
        return 'No json in request'

@app.route('/scanner', methods=['GET'])
def list_scanners():
    # Get all scanner from the operator namespace
    returnThis={}
    group = 'samma.io' # str | The custom resource's group name
    version = 'v1' # str | The custom resource's version
    namespace = _NS # str | The custom resource's namespace
    plural = 'scanner' # str | The custom resource's plural name. For TPRs this would be lowercase plural kind.

    try:
        api_response = k8sapi.list_namespaced_custom_object(group, version, namespace, plural)
        returnThis=api_response
    except ApiException as e:
        print("Exception when listing scanners in the cluster: %s\n" % e)
     
    return returnThis


@app.route('/scanner', methods=['DELETE'])
def delete_scanners():
    if request.is_json:
        content = request.get_json()
        group = 'samma.io' # str | The custom resource's group name
        version = 'v1' # str | The custom resource's version
        namespace = _NS # str | The custom resource's namespace
        plural = 'scanner' # str | The custom resource's plural name. For TPRs this would be lowercase plural kind.
        name = content['name']
        grace_period_seconds = 0
        try:
            api_response = k8sapi.delete_namespaced_custom_object(group, version, namespace, plural, name, grace_period_seconds=grace_period_seconds)
            print(api_response)
            print("Scanner with name has bean delete {0}".format(name))
            return 'Done'
        except ApiException as e:
            print("Exception when listing scanners in the cluster: %s\n" % e)
    else:
        return 'No json in request {0}'.format(content)
    


@app.route('/target', methods=['GET'])
def list_targets():
    try:
        items = k8sapi.list_namespaced_custom_object(_GROUP, _VERSION, _NS, _PLURAL).get('items', [])
    except ApiException as e:
        return {"error": str(e)}, 500

    target_map = {}
    for item in items:
        spec = item.get('spec', {})
        t = spec.get('target')
        if t:
            key = (t, spec.get('samma_io_id'))
            target_map.setdefault(key, []).append(item['metadata']['name'])

    return {"targets": [
        {"target": t, "samma_io_id": tid, "scanners": sorted(names)}
        for (t, tid), names in sorted(target_map.items(), key=lambda kv: (kv[0][0], str(kv[0][1])))
    ]}, 200


@app.route('/target', methods=['PUT'])
def create_target():
    if not request.is_json:
        return {"error": "request must be JSON"}, 400
    content = request.get_json()
    target = (content.get('target') or '').strip()
    if not target:
        return {"error": "missing required field: target"}, 400
    if not is_valid_target(target):
        return {"error": "invalid target: must be an IP address or RFC 1123 hostname"}, 400

    profile = content.get('profile', 'default')
    scheduler = content.get('scheduler', '')
    tags = content.get('samma_io_tags', samma_io_tags)
    if isinstance(tags, str):
        tags = [t.strip().strip("'\"") for t in tags.strip('[]').split(',') if t.strip()]
    env_fields = {
        'samma_io_id':   content.get('samma_io_id', samma_io_id),
        'samma_io_tags': tags,
        'samma_io_json': content.get('samma_io_json', samma_io_json),
        'write_to_file': content.get('write_to_file', write_to_file),
        'elasticsearch': content.get('elasticsearch', elasticsearch),
    }

    resolved = resolve_profiles([profile], core_v1_api)
    if not resolved:
        return {"error": "unknown or empty profile: {0}".format(profile)}, 400

    post_target_to_api(target, env_fields['samma_io_id'])

    created, skipped = [], []
    for scanner, template in resolved:
        name = make_crd_name(scanner, env_fields['samma_io_id'], template)
        spec = {
            "target": target,
            "scanners": [scanner],
            "samma_io_id": env_fields['samma_io_id'],
            "samma_io_tags": env_fields['samma_io_tags'],
            "samma_io_json": env_fields['samma_io_json'],
            "write_to_file": env_fields['write_to_file'],
            "elasticsearch": env_fields['elasticsearch'],
        }
        if scheduler:
            spec["scheduler"] = scheduler
        if template:
            spec["templates"] = [template]

        body = {"apiVersion": "samma.io/v1", "kind": "Scanner",
                "metadata": {"name": name, "namespace": _NS}, "spec": spec}
        try:
            k8sapi.create_namespaced_custom_object(_GROUP, _VERSION, _NS, _PLURAL, body)
            created.append(name)
        except ApiException as e:
            if e.status == 409:
                skipped.append(name)
            else:
                return {"error": str(e), "created": created, "skipped": skipped}, 500

    status = 207 if skipped else 201
    return {"target": target, "profile": profile, "created": created, "skipped": skipped}, status


@app.route('/target', methods=['DELETE'])
def delete_target():
    if not request.is_json:
        return {"error": "request must be JSON"}, 400
    content = request.get_json()
    target = (content.get('target') or '').strip()
    if not target:
        return {"error": "missing required field: target"}, 400
    target_id = content.get('samma_io_id')

    try:
        items = k8sapi.list_namespaced_custom_object(_GROUP, _VERSION, _NS, _PLURAL).get('items', [])
    except ApiException as e:
        return {"error": str(e)}, 500

    # With a samma_io_id in the body only that tenant's scanners are deleted;
    # without one, every Scanner for the target is removed as before.
    to_delete = [
        i for i in items
        if i.get('spec', {}).get('target') == target
        and (target_id is None or str(i.get('spec', {}).get('samma_io_id')) == str(target_id))
    ]
    if not to_delete:
        return {"error": "no Scanner CRDs found for target: {0}".format(target)}, 404

    deleted, errors = [], []
    for item in to_delete:
        name = item['metadata']['name']
        try:
            k8sapi.delete_namespaced_custom_object(_GROUP, _VERSION, _NS, _PLURAL, name, grace_period_seconds=0)
            deleted.append(name)
        except ApiException as e:
            errors.append({"name": name, "error": str(e)})

    return {"target": target, "deleted": deleted, "errors": errors}, (207 if errors else 200)


#
# This is the check to keep the pod alive
# if this fails k8s will restart the pod
@metrics.do_not_track()
@app.route('/health')
def health():
    return 'Im up and alive !'

#
# This is the check that lets the pod accepts trafffic
# if this fails k8s will not send any more traffic to this pod
@metrics.do_not_track()
@app.route('/ready')
def ready():
    return 'Im ready to work!'


#
# /metrics endpint is alive and send prometheus metrics
#  
#
#