{{- define "llm-gateway.labels" -}}
app.kubernetes.io/name: llm-gateway
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/owner: {{ .Values.owner }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end }}

{{- define "llm-gateway.selector" -}}
app.kubernetes.io/name: llm-gateway
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
