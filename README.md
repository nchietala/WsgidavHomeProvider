# WSGI Dav Home Provider

This is a library that includes a provider and domain controller
for use with wsgidav.

## Disclaimer
This library is in beta, is related to security, and as far as I
am aware has only been looked at by a single pair of eyes. *Use
it at your own risk.*

### HomeProvider
The home provider class is a provider that is capable of serving
different directories depending on the username of the user that
logs into the server. In theory this will work with any authentication
controller, but it is *strongly* recommended to user either the pam
controller, or the controller provided in this library because
other domain controllers will not be able to assure that a
logged in user has a home directory.

##### Usage
Set a provider mapping to use this provider, and change any
desired kwargs away from the default.
```yaml
provider_mapping:
    "/home":
        provider: WsgidavHomeProvider.HomeProvider
        kwargs: {}
```
See the `sample_config.yaml` file for valid kwargs

### PAMLockoutController
This is an child class of the PAMDomainController that keeps track
of how many times a remote host has attempted to log in, and will
throw a 429 error if a host fails to log in repeatedly.

##### Usage
Set the `http_authenticator: domain_controller:` to use this
controller, and adjust the `pam_dc: lockout:` as you see fit.

```yaml
http_authenticator:
    domain_controller: WsgidavHomeProvider.PAMLockoutController

pam_dc:
    lockout:
        timing: [4, 15]
```

Again, see the `sample_config.yaml` file for valid configuration
options.

If you are running wsgidav behind another server (such as apache
or nginx acting as an ssl terminator) that you have that server
setting the HTTP_X_FORWARDED_FOR header correctly, without it
all requests will be seen as coming from the same address.

## Installation

```
pip install https://github.com/nchietala/WsgidavHomeProvider/blob/main/dist/WsgidavHomeProvider-0.1.0.tar.gz?raw=true
```
