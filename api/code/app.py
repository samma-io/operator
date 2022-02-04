from turtle import write
from flask import Flask, render_template, request
import yaml
import json
import logging
import os
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


## Setup ENV 
samma_io_id = os.getenv('SAMMA_IO_ID' , '1234')
samma_io_tags = os.getenv('SAMMA_IO_TAGS' , ["samma"])
samma_io_json = os.getenv('SAMMA_IO_JSON' , "{'samma':'scanner'}") 
samma_io_scanners = os.getenv('SAMMA_IO_SCANNER' , ["nmap","nikto","tsunami"])
write_to_file = os.getenv('WRITE_TO_FILE' , 'true')
elasticsearch = os.getenv('ELASTICSEARCH' , 'true')


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
                "namespace": "samma-io"
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
        namespace = 'samma-io' # str | The custom resource's namespace
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