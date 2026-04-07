Add a new scanner to the Samma operator.

Usage: /add-scanner <scanner-name> [image]

Arguments:
- scanner-name: the scanner directory name, e.g. `traceroute-scanner`
- image: optional Docker image (default: `ghcr.io/samma-io/detect-<scanner-name>:latest`)

Steps to follow exactly:

1. Determine the image URL:
   - If an image argument was given, use it
   - Otherwise use `ghcr.io/samma-io/detect-<scanner-name>:latest`

2. Create `operator/code/scanners/<scanner-name>/job/<scanner-name>.yaml` using this exact Job template pattern (replace <scanner-name> and <image> with the real values):

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: {{ NAME }}
spec:
  template:
    spec:
      containers:
      - name: <scanner-name>
        image: <image>
        env:
          - name: TARGET
            value: {{ TARGET }}
          - name: SAMMA_IO_SCANNER
            value: <scanner-name>
        {% for user in ENV %}
          - name: {{ user }}
            value: "{{ ENV[user] }}"
        {% endfor %}
      restartPolicy: Never
```

3. Create `operator/code/scanners/<scanner-name>/cron/<scanner-name>.yaml` using this exact CronJob template pattern:

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: {{ NAME }}
spec:
  schedule: "{{ SCHEDULER }}"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: <scanner-name>
            image: <image>
            env:
              - name: TARGET
                value: {{ TARGET }}
              - name: SAMMA_IO_SCANNER
                value: <scanner-name>
            {% for user in ENV %}
              - name: {{ user }}
                value: "{{ ENV[user] }}"
            {% endfor %}
          restartPolicy: Never
```

4. In `operator/code/operator_handler.py`, find the `initOperator` function and the `scanner-profiles` ConfigMap definition. Append `<scanner-name>` to both the `"detect"` profile value and the `"all"` profile value (comma-separated).

5. Print the kubectl patch command the user needs to run to update the already-running ConfigMap in the cluster:
```
kubectl patch configmap scanner-profiles -n samma-io --type merge -p '{"data":{"detect":"<new detect value>","all":"<new all value>"}}'
```

6. Ask the user if they want to build and deploy now (docker build + push + kubectl rollout restart).
