{{- define "ci-dispatcher.name" -}}{{ .Release.Name | trunc 63 | trimSuffix "-" }}{{- end }}
{{- define "ci-dispatcher.selector" -}}
app.kubernetes.io/name: ci-dispatcher
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
{{- define "ci-dispatcher.labels" -}}
{{ include "ci-dispatcher.selector" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end }}
{{- define "ci-dispatcher.image" -}}
{{- if .Values.image.digest -}}
{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- else -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end -}}
{{- end }}
