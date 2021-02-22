# Authentication Use Cases

As a technical specification, Webauthn has "many ways" it case be used that *appear* to all be
valid. However, there is an unwritten set of combinations that are intended, and combinations
that can both cause confusion to users or allows verification bypasses at worst.

This document details the use cases that we support to understand how we should structure our library
to ensure it can never be used/held incorrectly.

> NOTE: This is not intended to be a simple introduction to webauthn, and will assume extensive prior
> knowledge.

## Key Terms

* Non-discoverable credential - https://www.w3.org/TR/webauthn-2/#credential-id

This is the "common" type of credential that is used. These are commonly implemented with a scheme
known as "key-wrapped-key". This is where the authenticator has a single private key, and encrypts
a credential with that key. The credential ID is the encrypted credential.

For the authenticator to then operate, it must be presented with the credential id, that the authenticator
decrypts and then uses in the authentication ceremony.

* Discoverable Credentials - https://www.w3.org/TR/webauthn-2/#client-side-discoverable-credential

A discoverable credential is previously called a resident key. This is when the *client* holds the
ability to find credentials locally rather than requiring them to be supplied in the allowedCredentials
set in authentication.

* User Verification - https://www.w3.org/TR/webauthn-2/#user-verification

The process of supplying extra or supplementary authentication to the authenticator. This improves
the authentication from "there is a person present" to "this specific owner of the authenticator" is
present. Conseder UV=True as the authenticator is a self container MFA device, where UV=false means that
the device is a SFA, and other authentication is required to compose a complete MFA.

At registration we store the policy and verification that was supplied in the internal Credential
type so that later decisions can be made for security policy.

## Authentication Work Flows

### Homogenous Non-Discoverable Credentials

This is a set of credentials with a homogeneous UV policy - either all discouraged or all required.

This policy is derived from the set of UV=true/false flags in the allow credential list. If the
UV flags are inconsistent an error is raised.

In the case all of these credentials are discouraged, we still assert that the UV bit matches
the returned authentication as it *is* valid for UV=true even when discouraged and we store that
in the credential.

* Example

A laptop where the user has multiple UV=false yubikeys that may be used as a authentication factor.

A user indicates they want to authenticate with their touchid as a self contained MFA. The user owns
and has enrolled multiple devices that have TouchID so any of them could be the credential in use
without external knowledge.


### Single Credential Non-Discoverable with UV Policy Override

If external knowledge is provided about which credential is intended to be used, we can have a credential's
requirements for verification temporarily overriden. This can be to remove the UV requirement, or
to temporarily require it.

* Example

Using a yubikey with pin as an MFA device, after login is used for privilege escalation where we only
need to assert a single factor (presence) at they are already authenticated.


### Single Credential Discoverable with UV Policy Override

With device specific information we can use a discoverable credential with policy override if required.
This could be considered as a device specific credential / authentication mechanism.

The other elements of "Single Credential Non-Discoverable with UV Policy Override" remain.

* Example

A longer term cookie on the device, or the device finger print indicates to the server that we can
use a discoverable credential from that device.

## Work flows that may not be relevant?

### Homogenous Discoverable Credentials

As a discoverable credential we already required external knowledge of what credential will be used
so does it become needed to have many discoverable credentials in one transaction?

## Questions?

* Can we assert that the returned key truly is discoverable after a registration so that we can store this boolean?
* In registration does UV=preferred, if we get UV=true, do we consider this credential to have been registerd under "required"?
