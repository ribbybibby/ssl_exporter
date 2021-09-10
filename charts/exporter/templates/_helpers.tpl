{{/*****************************************************************************

    General templates

*****************************************************************************/}}

{{- define "name" -}}{{- /******************************************************
Expand the name of the chart
***************************************************************************/ -}}
{{- $.Chart.Name | trunc 63 | trimSuffix "-" }}
{{- end }}


{{- define "releasename" -}}{{- /**********************************************
Expand the name of the instance
***************************************************************************/ -}}
{{- $.Release.Name | trunc 63 | trimSuffix "-" }}
{{- end }}


{{- define "labels" -}}{{- /****************************************************
Define controller labels
***************************************************************************/ -}}
app.kubernetes.io/name: {{ include "name" $ }}
helm.sh/chart: {{ $.Chart.Name }}-{{ $.Chart.Version | replace "+" "_" }}
app.kubernetes.io/managed-by: {{ $.Release.Service }}
app.kubernetes.io/instance: {{ $.Release.Name }}
app.kubernetes.io/version: {{ $.Chart.AppVersion }}
{{- end }}


{{- define "matchLabels" -}}{{- /**********************************************
	Define labels are used by controllers to find their pods
***************************************************************************/ -}}
app.kubernetes.io/name: {{ include "name" $ }}
app.kubernetes.io/managed-by: {{ $.Release.Service }}
app.kubernetes.io/instance: {{ $.Release.Name }}
{{- end }}

