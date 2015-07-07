# aws-iam

'aws-iam' provides LWRP to manage IAM elements.

## LWRPs

All LWRPs accepts the following parameters:

* region: Amazon region to use
* access_key_id: the access key to use
* secret_access_key: the secret to use

### certificate

Manage SSL certificates

#### parameters

* path: the path for the certificate. '/' by default
* private_key: the private key as a string
* certificate_body: the certificate as a string.
* certificate_chain: the certificates til the topmost CA. It can an string
of certificates concatenated or an array of certificates. The LWRP automatically
reorders the certificate to present a valid chain to Amazon
