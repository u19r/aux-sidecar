# Aux Sidecar Helm library chart

Include this chart as a dependency and render the named `aux-sidecar.container`,
`aux-sidecar.volumes`, and `aux-sidecar.checksumAnnotations` templates inside the customer's
workload. A library chart cannot inject itself into an existing Deployment. It deliberately emits
no Service, Ingress, host port, or public control surface.

The sidecar remains bound to loopback. Kubernetes HTTP probes originate outside the container and
cannot reach that address through the pod IP, so the chart uses the dependency-free
`sidecar healthcheck live|ready` executable command. Set `healthcheck.binaryPath` only when an image
places the binary somewhere other than `/usr/local/bin/sidecar`.
