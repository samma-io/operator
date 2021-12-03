# Samma Security Scanner Operator

![Samma-io!](/assets/samma_logo.png)




## Samma Security Scanners
This scanner is part of the Samma Security Scanners

The Samma Security Scanners are all small openspurce scanners. That have ben docerixed and print there result in JSON format.
The result is then sent to ElasticSerarch for storage and displayed using Kibana ore Grafana.

To see all the scanners please go to [Samma.io](https://samma.io)


## Kubernetest Operator

This is a kubernetes operator that deploys scanners to your kubernetes cluster.
You can deploy scanners bytwo diffrent ways

### Yaml deploys of scanner
Then the Samma Operator is deploy it also setup the CRD for scanner.
When you add a new scanner using this Defintions a new scanner si deploys

```
apiVersion: samma.io/v1  
kind: Scanner
metadata: 
  name: samma-nmap     
  namespace: samma-io
spec: 
 target: www.samma.io
 scheduler: "2 19 * * *"
 samma_io_id: "12345"
 samma_io_tags: 
      - scanner
      - prod
 #samme_io_json: '{"attacke":"true"}'
 write_to_file: "true"
 elasticsearch: elasticsearch
 scanners: ['nmap']

```

### Automaticly deploys scanners 
Sammas operator also lissen for ingress and service changes. 
When a new ingress with the correct annotions are added to the cluster. Samma will deploy the correct scanners to the new endpint.


```


```

## Config

## Yamla deploys of scanners

This is the full yaml of a samma scanner deployed

```
apiVersion: samma.io/v1  
kind: Scanner
metadata: 
  name: samma-nmap     
  namespace: samma-io
spec: 
 target: www.samma.io
 scheduler: "2 19 * * *"
 samma_io_id: "12345"
 samma_io_tags: 
      - scanner
      - prod
 #samme_io_json: '{"attacke":"true"}'
 write_to_file: "true"
 elasticsearch: elasticsearch
 scanners: ['nmap']
```


#### namespace: samma-io 
We always try to keep the scanners in the same namespace and use samma-io for that. The operator will deploy some configfiles that are then used by the scanners in that namespace.


#### target: www.samma.io
This is the target you want to scan. Jobs are created using this name.

#### scheduler: "2 19 * * *"
This will change the job to a cronjob if present. And then deploy cronjob using the cron settins

### samma_io 
All samma_io tags can be used to group and select scanners. Use them to sepperate diffrent scans from ethoder.
the values will be added to all logs that are then send to elastic and can then be used to search for scans with kibana.

#### samma_io_id: "12345"
Id if your taget example gitsha


#### samma_io_tags 
Add tags like prod / int ore your apps name here.

### samma_io_json
here you can add your custom JSON that will be added to the result


### write_to_file: "true"
This tell the scanners to write the result to a file and not only stout.
You can then read this file and send it to any tool you like


### elasticsearch: elasticsearch
Deploy the build in filebeat that reads the file and send it to elasticsearch. Filebeat will use the config in samma-io namespace to send the file.
If you ned update then uppdate that file.
(Tip this file can be modified to add other endpint that filebeat supports)

### scanners: ['nmap']
Add the scanners you want to be deployed and run.