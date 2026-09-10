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
{{- $parsed := fromYaml .Values.config -}}
{{- if and (kindIs "map" $parsed) (hasKey $parsed "Error") -}}
{{- fail (printf "values.config is not parseable YAML, so the termination grace period cannot be derived from shutdown_timeout: %v" (get $parsed "Error")) -}}
{{- end -}}
{{- $budget := int (default 30 (get $parsed "shutdown_timeout")) -}}
{{- if lt $budget 1 -}}{{- $budget = 30 -}}{{- end -}}
{{- add $budget 5 -}}
{{- end -}}
{{- end }}
