Add a new scanner to the Samma operator.

Usage: /add-scanner <scanner-name> [image]

Arguments:
- scanner-name: the scanner name, e.g. `traceroute-scanner`
- image: optional image reference (default: `ghcr.io/samma-io/detect-<scanner-name>:latest`)

Steps to follow exactly:

1. Determine the image reference:
   - If an image argument was given, use it
   - Otherwise use `ghcr.io/samma-io/detect-<scanner-name>:latest`

2. In `operator/code/jobspec.py`, add the scanner to the `SCANNERS` table. A detect-style scanner that reads `TARGET` from the environment and has one entrypoint is one line:

```python
SCANNERS["<scanner-name>"] = ScannerSpec("<scanner-name>", "<image>")
```

   Use the keyword arguments when the scanner needs more: `variants=[Variant("name", container=..., command=[...])]` for several entrypoints, `env={...}` for fixed extra variables, `args=<function taking the target>` when the target is an argument, `sudo=True` only when the image calls sudo, `raw_sockets=True` only for nmap-like SYN scanning. Do not add other capabilities or a writable root filesystem; `/out` and `/tmp` are the writable paths.

3. In `operator/code/operator_handler.py`, find `init_operator()` and the `scanner-profiles` ConfigMap definition. Append `<scanner-name>` to both the `"detect"` profile value and the `"all"` profile value (comma-separated).

4. In `operator/tests/test_jobspec.py`, add a test that builds a Job for the scanner with `jobspec.build_job` and checks the container name, image and `TARGET` env. Run from the repository root:
```
python3 -m unittest discover -s operator/tests -t operator
```

5. Add the scanner to the tables in `README.md` ("Scanner types") and mention it in `CLAUDE.md` if it is not a plain detect scanner.

6. Print the kubectl patch command the user needs to run to update the already-running ConfigMap in the cluster:
```
kubectl patch configmap scanner-profiles -n samma-io --type merge -p '{"data":{"detect":"<new detect value>","all":"<new all value>"}}'
```

7. Ask the user if they want to build and deploy now (docker build + push + kubectl rollout restart).
