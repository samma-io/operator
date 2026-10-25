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
