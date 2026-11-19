{{- define "securitas.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "securitas.fullname" -}}
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

{{- define "securitas.selectorLabels" -}}
app.kubernetes.io/name: {{ include "securitas.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "securitas.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "securitas.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "securitas.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "securitas.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "securitas.keySecret" -}}
{{- .Values.settings.secretKey.existingSecret | default (printf "%s-key" (include "securitas.fullname" .)) }}
{{- end }}

{{- define "securitas.adminSecret" -}}
{{- .Values.auth.admin.existingSecret | default (printf "%s-admin" (include "securitas.fullname" .)) }}
{{- end }}

{{- define "securitas.dbSecret" -}}
{{- if .Values.database.bundled.enabled }}{{ printf "%s-db" (include "securitas.fullname" .) }}{{ else }}{{ .Values.database.external.passwordSecret.name }}{{ end }}
{{- end }}

{{- define "securitas.dbHost" -}}
{{- if .Values.database.bundled.enabled }}{{ printf "%s-postgres" (include "securitas.fullname" .) }}{{ else }}{{ .Values.database.external.host }}{{ end }}
{{- end }}

{{- define "securitas.roleMap" -}}
{{- $out := list }}{{ range $g, $r := .Values.auth.roleMappings }}{{ $out = append $out (printf "%s=%s" $g $r) }}{{ end }}{{ join "," $out }}
{{- end }}
