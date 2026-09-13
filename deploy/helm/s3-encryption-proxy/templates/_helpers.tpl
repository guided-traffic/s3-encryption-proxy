{{/*
Expand the name of the chart.
*/}}
{{- define "s3-encryption-proxy.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "s3-encryption-proxy.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "s3-encryption-proxy.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "s3-encryption-proxy.labels" -}}
helm.sh/chart: {{ include "s3-encryption-proxy.chart" . }}
{{ include "s3-encryption-proxy.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "s3-encryption-proxy.selectorLabels" -}}
app.kubernetes.io/name: {{ include "s3-encryption-proxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "s3-encryption-proxy.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "s3-encryption-proxy.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the name of the config map
*/}}
{{- define "s3-encryption-proxy.configMapName" -}}
{{- if .Values.configMap.existingConfigMapName -}}
{{- .Values.configMap.existingConfigMapName -}}
{{- else -}}
{{- include "s3-encryption-proxy.fullname" . }}-config
{{- end -}}
{{- end }}

{{/*
Create the name of the secret
*/}}
{{- define "s3-encryption-proxy.secretName" -}}
{{ include "s3-encryption-proxy.fullname" . }}-secrets
{{- end }}

{{/*
Create the name of the certificate
*/}}
{{- define "s3-encryption-proxy.certificateName" -}}
{{ include "s3-encryption-proxy.fullname" . }}-tls
{{- end }}

{{/*
Pod labels
*/}}
{{- define "s3-encryption-proxy.podLabels" -}}
{{- if .Values.podLabels }}
{{- toYaml .Values.podLabels }}
{{- end }}
{{- end }}

{{/*
Termination grace period, derived from the proxy's own shutdown budget
(ADR 0015 D5). shutdown_timeout is the budget an in-flight transfer gets when
the process is asked to stop; the platform must not kill the pod before it has
expired, so the grace period is that value plus five seconds. An unset or zero
shutdown_timeout means the proxy's own 30-second fallback.

The value is read out of the rendered config rather than duplicated in a second
values key: two numbers that have to agree drift, and the one that loses is the
one nobody looks at. A config that does not parse is a render-time failure, not
a pod that is killed mid-transfer.
*/}}
{{- define "s3-encryption-proxy.terminationGracePeriodSeconds" -}}
{{- if .Values.terminationGracePeriodSeconds -}}
{{- .Values.terminationGracePeriodSeconds -}}
{{- else -}}
{{- $parsed := include "s3-encryption-proxy.parsedConfig" . | fromYaml -}}
{{- $budget := int (default 30 (get $parsed "shutdown_timeout")) -}}
{{- if lt $budget 1 -}}{{- $budget = 30 -}}{{- end -}}
{{- add $budget 5 -}}
{{- end -}}
{{- end }}

{{/*
values.config, parsed once and refused once. Two templates read it -- the
termination grace period and the probe scheme -- and a config that does not
parse must fail the render with one message rather than two, or crashloop the
pod at runtime with none.
*/}}
{{- define "s3-encryption-proxy.parsedConfig" -}}
{{- $parsed := fromYaml .Values.config -}}
{{- if and (kindIs "map" $parsed) (hasKey $parsed "Error") -}}
{{- fail (printf "values.config is not parseable YAML: %v" (get $parsed "Error")) -}}
{{- end -}}
{{- toYaml $parsed -}}
{{- end }}

{{/*
The probe scheme, derived from the config the pod will actually receive. /health
is served by the S3 listener, so it speaks TLS as soon as the config sets
tls.enabled -- and a plaintext httpGet against a TLS listener gets a 400, so the
pod never goes Ready and says nothing about why.

Derived rather than given a values key of its own: two sources of truth for "is
this listener TLS" is how the trap gets rebuilt. probes.scheme exists for the one
case the chart cannot see the config at all, configMap.useExistingConfigMap.
*/}}
{{- define "s3-encryption-proxy.probeScheme" -}}
{{- if .Values.probes.scheme -}}
{{- .Values.probes.scheme -}}
{{- else if .Values.serviceTLS.enabled -}}
HTTPS
{{- else -}}
{{- $cfg := include "s3-encryption-proxy.parsedConfig" . | fromYaml -}}
{{- $tls := get $cfg "tls" -}}
{{- if and (kindIs "map" $tls) (get $tls "enabled") -}}HTTPS{{- else -}}HTTP{{- end -}}
{{- end -}}
{{- end }}

{{/*
One probe, with httpGet.scheme filled in when the operator did not state it. The
scheme has to reach the rendered manifest, not only the running probe: relying on
the Kubernetes default would pass a bring-up and fail anything that reads the
Deployment back.
*/}}
{{- define "s3-encryption-proxy.probe" -}}
{{- $probe := deepCopy .probe -}}
{{- $get := get $probe "httpGet" -}}
{{- if and (kindIs "map" $get) (not (hasKey $get "scheme")) -}}
{{- $_ := set $get "scheme" (include "s3-encryption-proxy.probeScheme" .root) -}}
{{- end -}}
{{- toYaml $probe -}}
{{- end }}

{{/*
Refuse a TLS configuration that does not do what it looks like it does. Called
from the Deployment, which always renders, so it runs on any install or template
of the whole chart.

Three rules, and each exists because a control that is only in the configuration is
worse than no control: it gets relied upon.

0. serviceTLS has a certificate to serve, and exactly one source for the tls:
   block (ADR 0026 D3, D5).
1. An enabled Ingress terminates TLS for every host it serves. This proxy exists
   to keep object data confidential (ADR 0001); an Ingress that answers a host in
   plaintext puts the client's credentials and object keys on the wire in front of
   it, and nothing in the rendered manifest says so.
2. A rendered cert-manager Certificate has a consumer. The chart does not mount it
   into the pod, so the only thing that can consume it is an ingress.tls entry
   naming its secret. Issuing a certificate nothing uses reads as "TLS is
   configured" and is not.
*/}}
{{- define "s3-encryption-proxy.validateTLS" -}}
{{- if .Values.serviceTLS.enabled -}}
{{- if and (not .Values.serviceTLS.existingSecret) (not .Values.serviceTLS.issuer.name) -}}
{{- fail "serviceTLS.enabled is true with no way to get a certificate: set serviceTLS.existingSecret to a Secret holding tls.crt and tls.key, or serviceTLS.issuer.name to a cert-manager issuer. Without one the pod starts, cannot read its certificate and crashloops." -}}
{{- end -}}
{{- $cfg := include "s3-encryption-proxy.parsedConfig" . | fromYaml -}}
{{- if hasKey $cfg "tls" -}}
{{- fail "serviceTLS.enabled is true and values.config already carries a tls: block. The chart adds one (ADR 0026), and two sources for one setting drift. Remove the tls: block from config, or set serviceTLS.enabled: false and keep configuring it by hand." -}}
{{- end -}}
{{- end -}}
{{- if .Values.monitoring.enabled -}}
{{- $cfg := include "s3-encryption-proxy.parsedConfig" . | fromYaml -}}
{{- if hasKey $cfg "monitoring" -}}
{{- fail "monitoring.enabled is true and values.config already carries a monitoring: block. The chart adds one, and two sources for one setting drift. Remove the monitoring: block from config, or set monitoring.enabled: false and keep configuring it by hand." -}}
{{- end -}}
{{- end -}}
{{- if .Values.ingress.enabled -}}
{{- if not .Values.ingress.tls -}}
{{- fail "ingress.enabled is true but ingress.tls is empty: the Ingress would answer in plaintext, and this proxy exists to keep that data confidential. Add an ingress.tls entry, or set ingress.enabled: false." -}}
{{- end -}}
{{- $secured := dict -}}
{{- range .Values.ingress.tls -}}
{{- range .hosts -}}
{{- $_ := set $secured . true -}}
{{- end -}}
{{- end -}}
{{- range .Values.ingress.hosts -}}
{{- if not (hasKey $secured .host) -}}
{{- fail (printf "ingress host %q is in no ingress.tls entry, so the Ingress would answer it in plaintext. Add it to the hosts of a tls entry." .host) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if .Values.certificate.enabled -}}
{{- $wanted := .Values.certificate.secretName | default (include "s3-encryption-proxy.certificateName" .) -}}
{{- $consumed := false -}}
{{- range .Values.ingress.tls -}}
{{- if eq .secretName $wanted -}}{{- $consumed = true -}}{{- end -}}
{{- end -}}
{{- if not (and .Values.ingress.enabled $consumed) -}}
{{- /* A pod that mounts the certificate consumes it just as an Ingress does (ADR 0026 D7). */ -}}
{{- if not (and .Values.serviceTLS.enabled (eq (include "s3-encryption-proxy.serviceTLSSecretName" .) $wanted)) -}}
{{- fail (printf "certificate.enabled is true and nothing consumes secret %q: name it in an ingress.tls entry, point serviceTLS.existingSecret at it, or set certificate.enabled: false." $wanted) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end }}

{{/*
The Secret the pod mounts for its own listener: the one the operator brought, or
the one cert-manager is asked to fill.
*/}}
{{- define "s3-encryption-proxy.serviceTLSSecretName" -}}
{{- if .Values.serviceTLS.existingSecret -}}
{{- .Values.serviceTLS.existingSecret -}}
{{- else -}}
{{- printf "%s-service-tls" (include "s3-encryption-proxy.fullname" .) -}}
{{- end -}}
{{- end }}

{{/*
The names the in-cluster Service actually answers to, computed rather than
configured (ADR 0026 D2): a name the Service has and the certificate does not is a
failure the operator only sees when a client refuses the connection.
*/}}
{{- define "s3-encryption-proxy.serviceDNSNames" -}}
{{- $name := include "s3-encryption-proxy.fullname" . -}}
{{- $ns := .Release.Namespace -}}
{{- $names := list $name (printf "%s.%s" $name $ns) (printf "%s.%s.svc" $name $ns) (printf "%s.%s.svc.%s" $name $ns .Values.clusterDomain) -}}
{{- range .Values.serviceTLS.extraDNSNames -}}
{{- $names = append $names . -}}
{{- end -}}
{{- toYaml $names -}}
{{- end }}
