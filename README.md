# supermicro-ipmi-cert-upload

Usage: [options] ipmi_ip

| Name  | Type | Use | Default |
| ------------- | ------------- | ------------- | ------------- |
| base | string | certificates base path | current directory |
| cert | string | cert file name | ipmi_*[ip]*.crt |
| key | string | key file name | ipmi_*[ip]*.key |
| debug | bool | enable debug | false |
| username | string | ipmi login username | |
| password | string | ipmi login password | |
| reset | bool | reset bmc | false |
