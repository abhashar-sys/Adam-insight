{{/*
Expand the name of the chart.
*/}}
{{- define "adam-insight-traffic-intel-agent.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
Truncated to 63 chars because Kubernetes DNS labels have that limit.
*/}}
{{- define "adam-insight-traffic-intel-agent.fullname" -}}
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
Create chart label.
*/}}
{{- define "adam-insight-traffic-intel-agent.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels applied to all resources.
*/}}
{{- define "adam-insight-traffic-intel-agent.labels" -}}
helm.sh/chart: {{ include "adam-insight-traffic-intel-agent.chart" . }}
{{ include "adam-insight-traffic-intel-agent.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels — used by both the Deployment and the Service.
*/}}
{{- define "adam-insight-traffic-intel-agent.selectorLabels" -}}
app.kubernetes.io/name: {{ include "adam-insight-traffic-intel-agent.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
ServiceAccount name.
*/}}
{{- define "adam-insight-traffic-intel-agent.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "adam-insight-traffic-intel-agent.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}
