{{- /*
samma.image renders an image reference from a values block with image, tag
and digest: image@sha256:... when a digest is set, else image:tag, where an
empty tag means the chart's appVersion.

  {{ include "samma.image" (dict "spec" .Values.operator "chart" .Chart) }}
*/ -}}
{{- define "samma.image" -}}
{{- $spec := .spec -}}
{{- if $spec.digest -}}
{{- $digest := $spec.digest -}}
{{- if not (hasPrefix "sha256:" $digest) }}{{ $digest = printf "sha256:%s" $digest }}{{ end -}}
{{ $spec.image }}@{{ $digest }}
{{- else -}}
{{ $spec.image }}:{{ $spec.tag | default .chart.AppVersion }}
{{- end -}}
{{- end -}}

{{- /*
samma.consentGate stops the render until acceptScanningTerms is true. It is
included from every template that creates a workload, so the first error a
user sees is this one whatever order Helm renders the files in.
*/ -}}
{{- define "samma.consentGate" -}}
{{- if not .Values.acceptScanningTerms -}}
{{- fail (printf "\n\nsamma-operator scans the hosts this cluster's Ingresses serve.\n\nIt runs security scanners (TLS, HTTP headers, open ports, and with the classic scanners nmap, nikto and tsunami) from inside the cluster against every host of an Ingress you annotate, and against any target a Scanner resource names. Scanning hosts you do not own or are not allowed to test may break the law or your provider's terms of service.\n\nIf these are your hosts and you accept that, install with\n\n  --set acceptScanningTerms=true\n\nor put acceptScanningTerms: true in your values file.\n") -}}
{{- end -}}
{{- end -}}

{{- /*
samma.storeInTimescaleDB is "true" when the bridge should write rows:
TimescaleDB is deployed and bridge.storeInTimescaleDB is on.
*/ -}}
{{- define "samma.storeInTimescaleDB" -}}
{{- if and .Values.timescaledb.enabled .Values.bridge.storeInTimescaleDB }}true{{ end -}}
{{- end -}}

{{- /*
samma.timescaledbSecret names the Secret with the key "password".
*/ -}}
{{- define "samma.timescaledbSecret" -}}
{{- .Values.timescaledb.existingSecret | default "samma-timescaledb" -}}
{{- end -}}

{{- /*
samma.natsSecret names the Secret with the NATS passwords (keys
scanner-password and bridge-password) that the scanner pods and the bridge
log in with, or renders nothing when they connect without credentials.

  nats.auth.enabled=false            nothing: no credentials anywhere.
  nats.enabled=true (bundled NATS)   nats.existingSecret, else the chart's
                                     own samma-nats-auth.
  nats.enabled=false (external NATS) nats.existingSecret; the chart renders
                                     no Secret then, so the render fails
                                     without one rather than fall back to
                                     anonymous connections silently.
*/ -}}
{{- define "samma.natsSecret" -}}
{{- if .Values.nats.auth.enabled -}}
{{- if .Values.nats.enabled -}}
{{- .Values.nats.existingSecret | default "samma-nats-auth" -}}
{{- else if .Values.nats.existingSecret -}}
{{- .Values.nats.existingSecret -}}
{{- else -}}
{{- fail "\n\nnats.enabled=false (an external NATS at config.natsUrl) with nats.auth.enabled=true needs nats.existingSecret: a Secret with the keys scanner-password and bridge-password that the external NATS accepts for the users nats.auth.scannerUser and nats.auth.bridgeUser. Set nats.auth.enabled=false if the external NATS takes connections without credentials.\n" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- /*
samma.natsUrl is config.natsUrl; the render fails when it is empty, since
the operator, the bridge and every scanner pod connect to it.
*/ -}}
{{- define "samma.natsUrl" -}}
{{- required "config.natsUrl must name the NATS server (the bundled one is nats://nats:4222)" .Values.config.natsUrl -}}
{{- end -}}

{{- /*
samma.natsEgressRule renders the egress rule (a NetworkPolicyEgressRule list
entry) that lets a pod reach NATS: the bundled NATS pod by label, or with
nats.enabled=false the peers in networkPolicies.externalNats.to on its
ports, or those ports to any address when no peers are listed.
*/ -}}
{{- define "samma.natsEgressRule" -}}
{{- if .Values.nats.enabled }}
- to:
    - podSelector:
        matchLabels:
          app: nats
  ports:
    - port: 4222
      protocol: TCP
{{- else }}
# The external NATS at config.natsUrl (networkPolicies.externalNats).
- ports:
    {{- range .Values.networkPolicies.externalNats.ports }}
    - port: {{ . }}
      protocol: TCP
    {{- end }}
  {{- with .Values.networkPolicies.externalNats.to }}
  to:
    {{- toYaml . | nindent 4 }}
  {{- end }}
{{- end }}
{{- end -}}
