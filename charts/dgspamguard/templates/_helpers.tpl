{{- define "dgspamguard.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "dgspamguard.fullname" -}}
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

{{- define "dgspamguard.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "dgspamguard.labels" -}}
helm.sh/chart: {{ include "dgspamguard.chart" . }}
{{ include "dgspamguard.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: dgspamguard
{{- end }}

{{- define "dgspamguard.selectorLabels" -}}
app.kubernetes.io/name: {{ include "dgspamguard.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: api
{{- end }}

{{- define "dgspamguard.postgresql.fullname" -}}
{{- printf "%s-postgresql" (include "dgspamguard.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "dgspamguard.postgresql.selectorLabels" -}}
app.kubernetes.io/name: {{ include "dgspamguard.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: postgresql
{{- end }}

{{- define "dgspamguard.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "dgspamguard.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "dgspamguard.dbUrlSecretName" -}}
{{- if and (not .Values.database.internal.enabled) .Values.database.external.existingSecret }}
{{- .Values.database.external.existingSecret }}
{{- else }}
{{- include "dgspamguard.fullname" . }}
{{- end }}
{{- end }}

{{- define "dgspamguard.dbUrlSecretKey" -}}
{{- if and (not .Values.database.internal.enabled) .Values.database.external.existingSecret }}
{{- .Values.database.external.existingSecretKey }}
{{- else }}
{{- "database-url" }}
{{- end }}
{{- end }}

{{- define "dgspamguard.podSecurityContext" -}}
{{- if .Values.openshift.enabled }}
{{- $osc := omit .Values.podSecurityContext "runAsUser" "runAsGroup" "fsGroup" }}
{{- toYaml $osc }}
{{- else }}
{{- toYaml .Values.podSecurityContext }}
{{- end }}
{{- end }}

{{- define "dgspamguard.containerSecurityContext" -}}
{{- if .Values.openshift.enabled }}
{{- $csc := omit .Values.securityContext "runAsUser" "runAsGroup" }}
{{- toYaml $csc }}
{{- else }}
{{- toYaml .Values.securityContext }}
{{- end }}
{{- end }}
