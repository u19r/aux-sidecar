{{- define "aux-sidecar.container" -}}
- name: aux-sidecar
  image: "{{ .Values.auxSidecar.image.repository }}:{{ .Values.auxSidecar.image.tag }}"
  imagePullPolicy: {{ .Values.auxSidecar.image.pullPolicy }}
{{- if .Values.auxSidecar.image.command }}
  command:
{{ toYaml .Values.auxSidecar.image.command | indent 4 }}
{{- end }}
  args:
{{- if .Values.auxSidecar.image.args }}
{{ toYaml .Values.auxSidecar.image.args | indent 4 }}
{{- else }}
    - --preset=kubernetes
    - --bind-addr=127.0.0.1:9001
{{- if .Values.auxSidecar.socket.enabled }}
    - --unix-socket={{ .Values.auxSidecar.socket.path }}
{{- end }}
    - --resource-audience=$(AUX_RESOURCE_AUDIENCE)
{{- end }}
  env:
    - name: AUX_BASE_URL
      valueFrom: { secretKeyRef: { name: {{ .Values.auxSidecar.secretName }}, key: base-url } }
    - name: AUX_API_KEY
      valueFrom: { secretKeyRef: { name: {{ .Values.auxSidecar.secretName }}, key: api-key } }
    - name: AUX_RESOURCE_AUDIENCE
      valueFrom: { secretKeyRef: { name: {{ .Values.auxSidecar.secretName }}, key: resource-audience } }
  ports:
    - { name: sidecar, containerPort: 9001, protocol: TCP }
  startupProbe:
    exec:
      command: [{{ .Values.auxSidecar.healthcheck.binaryPath | quote }}, healthcheck, live]
    failureThreshold: 30
    periodSeconds: 1
  livenessProbe:
    exec:
      command: [{{ .Values.auxSidecar.healthcheck.binaryPath | quote }}, healthcheck, live]
  readinessProbe:
    exec:
      command: [{{ .Values.auxSidecar.healthcheck.binaryPath | quote }}, healthcheck, ready]
  resources:
{{ toYaml .Values.auxSidecar.resources | indent 4 }}
  securityContext:
{{ toYaml .Values.auxSidecar.securityContext | indent 4 }}
{{- if .Values.auxSidecar.socket.enabled }}
  volumeMounts:
    - { name: aux-sidecar-socket, mountPath: /var/run/aux-sidecar }
{{- end }}
{{- end }}

{{- define "aux-sidecar.volumes" -}}
{{- if .Values.auxSidecar.socket.enabled }}
- name: aux-sidecar-socket
  emptyDir: {}
{{- end }}
{{- end }}

{{- define "aux-sidecar.checksumAnnotations" -}}
checksum/aux-sidecar-config: {{ toJson .Values.auxSidecar | sha256sum }}
{{- end }}
