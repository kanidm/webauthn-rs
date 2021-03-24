# Authentication Use Cases

As a technical specification, Webauthn has "many ways" it case be used that *appear* to all be
valid. However, there is an unwritten set of combinations that are intended, and combinations
that can both cause confusion to users or allows verification bypasses at worst.

This document details the use cases that we support to understand how we should structure our library
to ensure it can never be used/held incorrectly.

> NOTE: This is not intended to be a simple introduction to webauthn, and will assume extensive prior
> knowledge.

## Key Terms

### Non-discoverable credential

[credential-id w3c](https://www.w3.org/TR/webauthn-2/#credential-id)

This is the "common" type of credential that is used. These are commonly implemented with a scheme
known as "key-wrapped-key". This is where the authenticator has a single private key, and encrypts
a credential with that key. The credential ID is the encrypted credential.

For the authenticator to then operate, it must be presented with the credential id, that the authenticator
decrypts and then uses in the authentication ceremony.

### Discoverable Credentials

[discoverable credential w3c](https://www.w3.org/TR/webauthn-2/#client-side-discoverable-credential)

A discoverable credential is previously called a resident key. This is when the *client* holds the
ability to find credentials locally rather than requiring them to be supplied in the allowedCredentials
set in authentication.

### User Verification

[user verification w3c](https://www.w3.org/TR/webauthn-2/#user-verification)

The process of supplying extra or supplementary authentication to the authenticator. This improves
the authentication from "there is a person present" to "this specific owner of the authenticator" is
present. Conseder UV=True as the authenticator is a self container MFA device, where UV=false means that
the device is a SFA, and other authentication is required to compose a complete MFA.

At registration we store the policy and verification that was supplied in the internal Credential
type so that later decisions can be made for security policy.

### External Knowledege

This is where using elements from the user interaction, workflow, or a device fingerprint, cookie
or other, the client or RP can make descions about which credential or policy to use before
the initial webauthn challenge is sent.

This work flow could be a user login page that requests "how" the user wishes to authenticate,
which device they want to use. It could also be based on the device ID and understanding that
the authenticator is part of the device, so we should prefer it's use.

## Authentication Work Flows

### Homogenous Non-Discoverable Credentials

This is a set of credentials with a homogeneous UV policy - either all discouraged or all required.

This policy is derived from the set of UV=true/false flags in the allow credential list. If the
UV flags are inconsistent an error is raised.

In the case all of these credentials are discouraged, we still assert that the UV bit matches
the returned authentication as it *is* valid for UV=true even when discouraged and we store that
in the credential.

#### Example

A laptop where the user has multiple UV=false yubikeys that may be used as a authentication factor.

A user indicates they want to authenticate with their touchid as a self contained MFA. The user owns
and has enrolled multiple devices that have TouchID so any of them could be the credential in use
without external knowledge.

#### Detailed Example

This has many interactions with the UV policy at registration, and what the resulting states and outcomes
are.

| UV Policy | UV boolean returned | Valid UV Policies for Auth | UV boolean always checked in auth |
| --------- | ------------------- | -------------------------- | --------------------------------- |
| discouraged | false             | discouraged                | No - device can not do UV |
| discouraged | true              | discouraged, required      | Yes - device always does UV |
| preferred   | false             | discouraged                | No - device can not do UV |
| preferred   | true              | discouraged, required      | No - device may not always send UV in discouraged mode |
| required    | false             | -                          | No - device can not be used |
| required    | true              | required                   | Yes - device should always performs UV |

From these we can then construct some possible scenarioes.

##### Scenario 1

* Registration Policy = discouraged.
* One yubikey which does not have a pin.
* TouchID

During an authentication with policy discouraged we can check:

* The yubikey sends UV false
* The touchID sends UV true due to the registration policy = discouraged + uv true flag.

If we perform an authentication with policy required, only the TouchID device could participate. We would then
assert UV=true

##### Scenario 2

* Registration Policy = preferred
* One yubikey which does not have a pin.
* TouchID

During an authentication with policy discouraged we can check:

* The yubikey sends UV false.
* The touchID UV flag is ignored since we do not know if the device always sends UV true.

If we perform an authentication with policy required, only the TouchID device could participate. We would
then assert UV=true

HINT: This is why preferred is bad :) it's not clear what it means.

##### Scenario 3

* Registration Policy = required
* One yubikey which DOES have a pin.
* TouchID

During an authentication with policy required we can check:

* The yubikey sends UV true
* The touchID sends UV true.

We could not perform authentication with UV discouraged as this would violate the assumption the user
held at registration that the device always requires verification.

### Single Credential Non-Discoverable with UV Policy Override

If external knowledge is provided about which credential is intended to be used, we can have a credential's
requirements for verification temporarily overriden. This can be to remove the UV requirement, or
to temporarily require it.

#### Example

Using a yubikey with pin as an MFA device, after login is used for privilege escalation where we only
need to assert a single factor (presence) at they are already authenticated.

#### Warning

This method does mean that the assumptions of the user around the devices verification state are
potentially violated as the user may or may not know under what conditions the UV is required
or not. It's probably better to always use the same policy as existed at registration for
the associated device.


### Single Credential Discoverable with UV Policy Override

With device specific information we can use a discoverable credential with policy override if required.
This could be considered as a device specific credential / authentication mechanism.

The other elements of "Single Credential Non-Discoverable with UV Policy Override" remain.

#### Example

A longer term cookie on the device, or the device finger print indicates to the server that we can
use a discoverable credential from that device.

#### Detailed Example

The user registers their devices touchid with UV true as a discoverable credential. A cookie is sent
to the device that identifies this device for future authentications as belonging to this user and
this credential association.

During authentication the presence of this cookie allows us to pre-select that this devices possible
credentials could be used. We send empty allowCredentials, but internally we select the set of
related discoverable credentials for the user. We validate that the supplied credential is one
of the selected credentials and passes UV as required.

If the devices cookie store is cleared, we may offer the user to re-associate the device id with
that set of authenticators to generate that cookie.

## Work flows that may not be relevant?

### Homogenous Discoverable Credentials

As a discoverable credential we already required external knowledge of what credential will be used
so does it become needed to have many discoverable credentials in one transaction?

## Questions?

* Can we assert that the returned key truly is discoverable after a registration so that we can store this boolean?
* In registration does UV=preferred, if we get UV=true, do we consider this credential to have been registerd under "required"?
