# Kubernetes Chart and Manifests

The chart files and kubernetes manifests are generated from the templates present in `/kubernetes/templates/chart/`.

Any required changes should be made in the templates and not in these files.

The generated Secret has two independent keys: `secret` verifies the source
provider HMAC, while `upstreamToken` is the optional relay-to-upstream bearer.
When `existingSecretName` is set, that Secret must provide both keys (the
second may be empty when downstream bearer authentication is not used). The
chart and vanilla Deployment expose `upstreamToken` only as
`GWP_UPSTREAMTOKEN`; do not put it in a ConfigMap, URL, command argument, or
repository file.
