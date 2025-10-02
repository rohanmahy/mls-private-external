---
title: "Private External Message extensions for Messaging Layer Security (MLS)"
abbrev: "MLS Private External Messages"
category: info

docname: draft-mahy-mls-private-external-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Messaging Layer Security"
keyword:
 - private external proposal
 - private external commit
 - private external join
 - private GroupContext
 - private ratchet tree
 - external proposal privacy
 - external commit privacy
 - external join privacy
 - GroupContext privacy
 - ratchet tree privacy
venue:
  group: "Messaging Layer Security"
  type: "Working Group"
  mail: "mls@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/mls/"
  github: "rohanmahy/mls-private-external"
  latest: "https://rohanmahy.github.io/mls-private-external/draft-mahy-mls-private-external.html"

author:
 -
    fullname: Rohan Mahy
    organization: Rohan Mahy Consulting Services
    email: rohan.ietf@gmail.com

normative:

informative:

...

--- abstract

MLS groups that use private handshakes lose member privacy when sending external proposals. This document addresses this shortcoming, by encrypting external proposals using the public key of the root of the MLS ratchet key. It also provides a mechanism to share this key and protect it from tampering by a malicious intermediary.

--- middle

# Introduction

The MLS protocol {{!RFC9420}} was designed to support both a model where the Distribution Service (DS) sees the contents of MLS handshake messages and often assumes a policy enforcement role, and a model where the DS is merely responsible for forwarding handshake messages and possibly enforcing ordering of messages.
In the first model clients send every handshake as a PublicMessage (or a SemiPrivateMessage {{?I-D.mahy-mls-semiprivatemessage}}), whereas in the second model the clients send in-group handshakes as a PrivateMessage.
As of this writing there are non-trivial commercial deployments using both the PublicMessage model (ex: Cisco, Amazon, Ring Central, Wire) and the PrivateMessage model (ex: Ephemera, Germ).

In the PrivateMessage model, group members enjoy substantially more privacy from the DS.
In the PublicMessage model, the DS usually can provide (authorized) non-members with enough information that they can join a group via an external commit.
Even in the PublicMessage model, some (usually large) groups use external proposals to join.
In the PrivateMessage model, (authorized) non-members can also join using external proposals (or rarely using external commits if the GroupInfo is shared by an existing member), however the joiner is currently forced to send the proposal (or commit) as a PublicMessage and therefore reveal potentially private information such as their credential and capabilities to the DS.

This extension allows groups using PrivateMessage to maintain the privacy of external handshake messages, by encrypting them to the (public) `encryption_key` of the root node of the ratchet tree.
It also provides a way to convey that public key safely to prevent active attacks.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Mechanism

## Additional information shared in every commit

Groups participating in this mechanism include a `root_private_signature_key` component (see {{Section 4.6 of !I-D.ietf-mls-extensions}}) in the GroupContext of type `RootPrivateSignature`, containing a unique random private signature key corresponding to the group's cipher suite.
Whenever a commit removes a member from a group, this component MUST be replaced with a new unique random private signature key.

Members sending a commit include one additional Additional Authentication Data (AAD) component (see {{Section 4.9 of !I-D.ietf-mls-extensions}}) of type `ExternalEncryptionInfo` in every commit (including commits sent in a `PrivateExternalMessage`).

> Note: SafeSignWithLabel is not used, because there are two different component IDs represented.

~~~ tls
struct {
    opaque root_private_signature_key<V>;
} RootPrivateSignature;

struct {
    ProtocolVersion version = mls10;
    opaque group_id<V>;
    uint64 epoch;
    CipherSuite ciphersuite;
    HPKEPublicKey root_public_hpke_key;
    SignaturePublicKey root_public_signature_key;
} ExternalEncryptionInfoTBS;

struct {
    CipherSuite ciphersuite;
    HPKEPublicKey root_public_hpke_key;
    SignaturePublicKey root_public_signature_key;
    /* SignWithLabel(root_private_signature_key, */
    /*    "ExternalEncryptionInfoTBS", ExternalEncryptionInfoTBS) */
    opaque external_encryption_signature<V>;
} ExternalEncryptionInfo;
~~~

## Sending an external proposal or external commit to the group

A non-member client that wishes to send a message to the group, first constructs a `PublicMessage` called `external_message_plaintext`.
The `PrivateExternalMessage` wire format wraps that `external_message_plaintext`, by encrypting it to the HPKE public key of the root of the ratchet tree (the root Node's `ParentNode.encryption_key`).
`PrivateExternalMessage` is defined below.

~~~ tls
/*  PublicMessage.content.sender.sender_type != member  */
PublicMessage external_message_plaintext;

encrypted_public_message = EncryptWithLabel(root_public_hpke_key,
    "PrivateExternalMessageContent", PrivateExternalMessageContext,
    external_message_plaintext)

struct {
    /* PublicMessage (the plaintext) is pretty self contained */
} PrivateExternalMessageContext;

struct {
    opaque group_id<V>;
    uint64 epoch;
    ContentType content_type;
    opaque authenticated_data<V>;
    HPKECiphertext encrypted_public_message<V>;
} PrivateExternalMessage;

PrivateExternalMessage.authenticated_data =
   external_message_plaintext.content.authenticated_data

struct {
    ProtocolVersion version = mls10;
    WireFormat wire_format;
    select (MLSMessage.wire_format) {
        case mls_public_message:
            PublicMessage public_message;
        case mls_private_message:
            PrivateMessage private_message;
        ...
        case mls_private_external_message;
            PrivateExternalMessage private_external_message
    };
} MLSMessage;
~~~

## Decryption and verification by members

Members receiving a `PrivateExternalMessage` check that the `group_id` matches a known group and that the epoch is the current epoch.
They then decrypt and verify the `encrypted_public_message`.

~~~ tls
/* root_private_hpke_key is node_priv[<max>] */
external_message_plaintext = DecryptWithLabel(
    root_private_hpke_key,
    "PrivateExternalMessageContent", PrivateExternalMessageContext,
    encrypted_public_message.kem_output,
    encrypted_public_message.ciphertext)
~~~

They then verify the following values in the `PrivateExternalMessage` match their corresponding field in the `external_message_plaintext.content`:

- `group_id`,
- `epoch`,
- `content_type`, and
- `authenticated_data`

Finally, they process the `external_message_plaintext` as if it were a regular `PublicMessage`.

# Security Considerations

TODO Security


# IANA Considerations

TODO IANA


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
