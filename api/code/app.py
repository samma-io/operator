from flask import Flask, render_template, request
import yaml
import json
import logging
from kubernetes.client.rest import ApiException
from kubernetes import client, config, watch
from prometheus_flask_exporter import PrometheusMetrics



try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

# Load the kubernetes access
config.load_incluster_config()
k8sapi =client.CustomObjectsApi()

## Setup the flask app
app = Flask(__name__)
metrics = PrometheusMetrics(app)


#
#
# Making a webbpage to show scanners 
#

@app.route('/')
def hello_world():
    # Get all scanner from the samma-io namespace
    returnThis={}
    group = 'samma.io' # str | The custom resource's group name
    version = 'v1' # str | The custom resource's version
    namespace = 'samma-io' # str | The custom resource's namespace
    plural = 'scanner' # str | The custom resource's plural name. For TPRs this would be lowercase plural kind.

    try:
        api_response = k8sapi.list_namespaced_custom_object(group, version, namespace, plural)
        returnThis=api_response
    except ApiException as e:
        print("Exception when listing scanners in the cluster: %s\n" % e)
    return render_template('base.html', SCANNERS=returnThis['items'])


@app.route('/scanner', methods=['PUT'])
def create_scanners():
    if request.is_json:
        content = request.get_json()
        scanners = content['scanners']
        # For every scanner in json lets create scanners        
        for scanner in scanners:
            scannerJSON = {
                "apiVersion": "samma.io/v1",
                "kind": "Scanner",
                "metadata": {
                    "name": "{0}-{1}".format(scanner,content['target'].replace('.','-')),
                    "namespace": "samma-io"
                },
                "spec": {
                    "target": "{0}".format(content['target']),
                    "samma_io_id": "{0}".format(content['samma_io_id']),
                    "samma_io_tags": content['samma_io_tags'],
                    "write_to_file": "{0}".format(content['write_to_file']),
                    "elasticsearch": "{0}".format(content['elasticsearch']),

                }
                }
            toDeploy = yaml.dump(json.dumps(scannerJSON))
            # Add the scanner to the cluster as a CDR that the operator can read
            group = 'samma.io' # str | The custom resource's group name
            version = 'v1' # str | The custom resource's version
            namespace = 'samma-io' # str | The custom resource's namespace
            plural = 'scanner' # str | The custom resource's plural name. For TPRs this would be lowercase plural kind.
            body = scannerJSON # object | The JSON schema of the Resource to create.


            try:
                api_response = k8sapi.create_namespaced_custom_object(group, version, namespace, plural, body)
                print("Scanner with name  {0} has bean created".format(scanner,content['target'].replace('.','-')))
            except ApiException as e:
                print("Exception when installing the scanner into the cluster: %s\n" % e)
            #print(toDeploy) 



        return 'JSON posted'
    else:
        return 'No json in request'

@app.route('/scanner', methods=['GET'])
def list_scanners():
    # Get all scanner from the samma-io namespace
    returnThis={}
    group = 'samma.io' # str | The custom resource's group name
    version = 'v1' # str | The custom resource's version
    namespace = 'samma-io' # str | The custom resource's namespace
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
        namespace = 'samma-io' # str | The custom resource's namespace
        plural = 'scanner' # str | The custom resource's plural name. For TPRs this would be lowercase plural kind.
        name = content['name']
        try:
            api_response = k8sapi.delete_namespaced_custom_object(group, version, namespace, plural, name)
            print("Scanner with name has bean delete {0}".format(name))
        except ApiException as e:
            print("Exception when listing scanners in the cluster: %s\n" % e)
        





    return 'deleting'


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