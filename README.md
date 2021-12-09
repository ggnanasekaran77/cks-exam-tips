# CKS Exam Hints

## Useful Links 

- https://github.com/walidshaari/Certified-Kubernetes-Security-Specialist#books 

- https://github.com/kodekloudhub/certified-kubernetes-security-specialist-cks-course/tree/main/docs/08-Mock-Exams


## Labs Practice

- KodeKloud Mock Exams
- ACloudGuru Labs



## CKS KodeKloud Mock Exam solution video

- https://www.youtube.com/watch?v=7eH7vfT0axA&list=PLglXbBWxN2H9-ATq0ShHVlMWskhRgvdJz


## Useful Bookmarks 

kubectl Cheat Sheet -- https://kubernetes.io/docs/reference/kubectl/cheatsheet/

Kubectl Commands -- https://kubernetes.io/docs/reference/generated/kubectl/kubectl-commands

Network Policies -- https://kubernetes.io/docs/concepts/services-networking/network-policies/

Security Context -- https://kubernetes.io/docs/tasks/configure-pod-container/security-context/

Secrets -- https://kubernetes.io/docs/concepts/configuration/secret/

RBAC -- https://kubernetes.io/docs/reference/access-authn-authz/rbac/

Seccomp -- https://kubernetes.io/docs/tutorials/clusters/seccomp/

Apparmor -- https://kubernetes.io/docs/tutorials/clusters/apparmor/

ImageWebhookPolicy -- https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/

Audit Policy -- https://kubernetes.io/docs/tasks/debug-application-cluster/audit/

PodSecurityPolicy -- https://kubernetes.io/docs/concepts/policy/pod-security-policy/

Kubelet Config -- https://kubernetes.io/docs/reference/config-api/kubelet-config.v1beta1/

RuntimeClaas -- https://kubernetes.io/docs/concepts/containers/runtime-class/

Admission Controllers -- https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#podsecuritypolicy

automountServiceAccountToken -- https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/

Pod Volumes -- https://kubernetes.io/docs/concepts/storage/volumes/

PV PVC -- https://kubernetes.io/docs/tasks/configure-pod-container/configure-persistent-volume-storage/

Ingress -- https://kubernetes.io/docs/concepts/services-networking/ingress/


## Useful Commands

```bash
crictl -r /var/run/containerd/containerd.sock pods

crictl -r /var/run/containerd/containerd.sock ps

crictl -r /var/run/containerd/containerd.sock logs -f ef86e6ecf0bcb
```

## Fix CIS Benchmark Issues

<details><summary>show</summary>
<p>

### kubelet
```yaml
vim /var/lib/kubelet/config.yaml
authentication:
  anonymous:
    enabled: false
  webhook:
    enabled: true
authorization:
  mode: Webhook
protectKernelDefaults: true

systemctl restart kubelet.service
systemctl status kubelet.service
```

### kube-apiserver
```bash
vim /etc/kubernetes/manifests/kube-apiserver.yaml
- --authorization-mode=Node,RBAC
- --profiling=false
```

### etcd
```bash
mv /etc/kubernetes/manifests/etcd.yaml /etc/kubernetes/
vim /etc/kubernetes/etcd.yaml
- --client-cert-auth=true
```

</p>
</details>

## Configure Admission Control | ImageWebhookPolicy

<details><summary>show</summary>
<p>

### admission-control.conf
```yaml
vim /etc/kubernetes/admission-control/admission-control.conf
apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
- name: ImagePolicyWebhook
  path: imagepolicy.conf
```

### imagepolicy.conf | imagepolicy.json
```bash
vim /etc/kubernetes/admission-control/imagepolicy.conf
{
   "imagePolicy": {
      "kubeConfigFile": "/etc/kubernetes/admission-control/imagepolicy_backend.kubeconfig",
      "allowTTL": 50,
      "denyTTL": 50,
      "retryBackoff": 500,
      "defaultAllow": false 
   }
}
Note: Change true to false and Take note of kubeConfigFile 
```

### imagepolicy_backend.kubeconfig 
```yaml
vim /etc/kubernetes/admission-control/imagepolicy_backend.kubeconfig
apiVersion: v1
kind: Config
clusters:
- name: trivy-k8s-webhook
  cluster:
    certificate-authority: /etc/kubernetes/admission-control/imagepolicywebhook-ca.crt
    server: https://acg.trivy.k8s.webhook:8090/scan
contexts:
- name: trivy-k8s-webhook
  context:
    cluster: trivy-k8s-webhook
    user: api-server
current-context: trivy-k8s-webhook
preferences: {}
users:
- name: api-server
  user:
    client-certificate: /etc/kubernetes/admission-control/api-server-client.crt
    client-key: /etc/kubernetes/admission-control/api-server-client.key
# Note: Edit server value
```

### kube-apiserver
```bash
vim /etc/kubernetes/manifests/kube-apiserver.yaml
- --admission-control-config-file=/etc/kubernetes/admission-control/admission-control.conf
- --enable-admission-plugins=NodeRestriction,ImagePolicyWebhook
```

</p>
</details>

## Audit Policy

<details><summary>show</summary>
<p>

### audit-policy.yaml
```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
omitStages:
  - "RequestReceived"
rules:
  - level: None
    resources:
    - group: ""
      resources: ["pods/log", "pods/status"]
  - level: RequestResponse
    resources:
    - group: ""
      resources: ["configmaps"]
  - level: Request
    resources:
    - group: ""
      resources: ["services", "pods"]
    namespaces: ["web"]
  - level: Metadata
    resources:
    - group: ""
      resources: ["secrets"]
  - level: Metadata
  ```

### kube-apiserver.yaml
```bash
vim /etc/kubernetes/manifests/kube-apiserver.yaml
- --audit-policy-file=/etc/kubernetes/audit-policy.yaml
- --audit-log-path=/var/log/kubernetes/audit.log
- --audit-log-maxage=10
- --audit-log-maxbackup=1
```

</p>
</details>


## PodSecurityPolicy

<details><summary>show</summary>
<p>

```yaml
vim  nopriv-psp.yml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: nopriv-psp
spec:
  privileged: false
  runAsUser:
    rule: "RunAsAny"
  fsGroup:
    rule: "RunAsAny"
  seLinux:
    rule: "RunAsAny"
  supplementalGroups:
    rule: "RunAsAny"
k apply -f nopriv-psp.yml
```

```yaml
/home/cloud_user/use-nopriv-psp.yml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: use-nopriv-psp
rules:
- apiGroups: ['policy']
  resources: ['podsecuritypolicies']
  verbs:     ['use']
  resourceNames:
  - nopriv-psp
k apply -f /home/cloud_user/use-nopriv-psp.yml
```

```yaml
/home/cloud_user/hoth-sa-use-nopriv-psp.yml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: hoth-sa-use-nopriv-psp
roleRef:
  kind: ClusterRole
  name: use-nopriv-psp
  apiGroup: rbac.authorization.k8s.io
subjects:
- kind: ServiceAccount
  name: hoth-sa
  namespace: hoth
k apply -f /home/cloud_user/hoth-sa-use-nopriv-psp.yml
```

</p>
</details>


## RuntimeClass | gVisor

<details><summary>show</summary>
<p>

### RuntimeClass
```yaml
vim /home/cloud_user/sandbox.yml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: sandbox
handler: runsc
k apply -f /home/cloud_user/sandbox.yml
```

### Edit deployment
```bash
k -n sunnydale edit deployments.apps buffy # runtimeClassName: sandbox
k -n sunnydale edit deployments.apps giles
k -n sunnydale edit deployments.apps spike
```

### Verification
```bash
k -n sunnydale exec buffy-7bdbdfc554-ls5q5 -- dmesg

[   0.000000] Starting gVisor...
[   0.453650] Forking spaghetti code...
[   0.939306] Conjuring /dev/null black hole...
[   1.162591] Searching for socket adapter...
[   1.450979] Generating random numbers by fair dice roll...
[   1.907884] Waiting for children...
[   2.063679] Checking naughty and nice process list...
[   2.554570] Recruiting cron-ies...
[   3.023213] Gathering forks...
[   3.300373] Synthesizing system calls...
[   3.401099] Searching for needles in stacks...
[   3.521588] Setting up VFS2...
[   3.938928] Ready!
```

</p>
</details>


## Security Best Practices
<details><summary>show</summary>
<p>

- Fixing issues in Dockerfile
- Fixing issues in Deployment

</p>
</details>

## Ensure Containers Are Static and Immutable

<details><summary>show</summary>
<p>

- runAsUser: 0
- readOnlyRootFilesystem: false
- priveledged: true

</p>
</details>


## Trivy Commands

<details><summary>show</summary>
<p>

```bash
k -n development get pods
k -n development get pods --output=custom-columns="NAME:.metadata.name,IMAGE:.spec.containers[*].image"
NAME       IMAGE
work1      busybox:1.33.1
work2      nginx:1.14.2
work3      amazonlinux:2
work4      amazonlinux:1
work5      centos:7
trivy image -s HIGH,CRITICAL busybox:1.33.1
trivy image -s HIGH,CRITICAL nginx:1.14.2 #HIGH and CRITICAL
trivy image -s HIGH,CRITICAL amazonlinux:2
trivy image -s HIGH,CRITICAL amazonlinux:1
trivy image -s HIGH,CRITICAL centos:7 #HIGH and CRITICAL
```

</p>
</details>

## Falco rules

<details><summary>show</summary>
<p>

```bash
sudo falco -M 45 -r /home/cloud_user/monitor_rules.yml > /home/cloud_user/falco_output.log
```

```bash
- /etc/falco/falco_rules.local.yaml
- /etc/falco/falco_rules.yaml
- /etc/falco/falco.yaml
systemctl restart falco.service
```


</p>
</details>


## AppArmor Profile

<details><summary>show</summary>
<p>

```bash
cat k8s-deny-write
#include <tunables/global>
profile k8s-deny-write flags=(attach_disconnected) {
  #include <abstractions/base>
  file,
  # Deny all file writes.
  deny /** w,
}
sudo aa-status | grep k8s-deny-write

sudo apparmor_parser k8s-deny-write

sudo aa-status | grep k8s-deny-write
   k8s-deny-write
```


```yaml
vim ~/writedeny.yml
apiVersion: v1
kind: Pod
metadata:
  name: writedeny
  namespace: dev
  annotations:
    container.apparmor.security.beta.kubernetes.io/busybox: localhost/k8s-deny-write
spec:
  containers:
  - name: busybox
    image: busybox:1.33.1
    command: ['sh', '-c', 'while true; do echo writedeny > password.txt; sleep 5; done']
# Note: annotations, container and apparmor profile to be edited
# container.apparmor.security.beta.kubernetes.io/<<container name>>: localhost/<<profile name>>
```
</p>
</details>


## Other topics
- Seccomp Profile
- Fix a Pod's Service Account That Has Too Many Permissions
- Create a Network Policy
- Get a Username, Password from an Existing Secret. Create a Secret and Mount It to a Pod
- automountServiceAccountToken: false