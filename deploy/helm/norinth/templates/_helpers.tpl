{{- define "norinth.name" -}}{{ .Chart.Name }}{{- end -}}
{{- define "norinth.fullname" -}}{{ printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" }}{{- end -}}
{{- define "norinth.labels" -}}
app.kubernetes.io/name: {{ include "norinth.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Values.image.tag | default .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}
{{- define "norinth.selectorLabels" -}}
app.kubernetes.io/name: {{ include "norinth.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- define "norinth.secretName" -}}{{ .Values.secrets.existingSecret | default (printf "%s-secrets" (include "norinth.fullname" .)) }}{{- end -}}
{{- define "norinth.dbSecretName" -}}{{ .Values.database.existingSecret | default (printf "%s-database" (include "norinth.fullname" .)) }}{{- end -}}
