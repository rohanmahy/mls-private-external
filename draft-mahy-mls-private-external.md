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
    email: rohan.ietf@gmail.com
 -
    fullname: Mojtaba Chenani
    organization: Ephemera
    email: chenani@outlook.com

normative:

informative:

--- abstract

MLS groups that use private handshakes lose member privacy when sending external proposals. This document addresses this shortcoming by encrypting external proposals using an HPKE public key derived from the epoch secret. It also provides a mechanism to share this key and protect it from tampering by a malicious intermediary.

--- middle

# Introduction

The MLS protocol {{!RFC9420}} was designed to support both a model where the Distribution Service (DS) sees the contents of MLS handshake messages and often assumes a policy enforcement role, and a model where the DS is merely responsible for forwarding handshake messages and possibly enforcing ordering of messages.
In the first model clients send every handshake as a PublicMessage (or a SemiPrivateMessage {{?I-D.mahy-mls-semiprivatemessage}}), whereas in the second model the clients send in-group handshakes as a PrivateMessage.
As of this writing there are non-trivial commercial deployments using both the PublicMessage model (ex: Cisco, Amazon, Ring Central, Wire) and the PrivateMessage model (ex: Ephemera, Germ).

In the PrivateMessage model, group members enjoy substantially more privacy from the DS.
In the PublicMessage model, the DS usually can provide (authorized) non-members with enough information that they can join a group via an external commit.
Even in the PublicMessage model, some (usually large) groups use external proposals to join.
In the PrivateMessage model, (authorized) non-members can also join using external proposals (or rarely using external commits if the GroupInfo is shared by an existing member), however the joiner is currently forced to send the proposal (or commit) as a PublicMessage and therefore reveal potentially private information such as their credential and capabilities to the DS.

This extension allows groups using PrivateMessage to maintain the privacy of external handshake messages by encrypting them to a public key derived from the group's epoch secret.
It also provides a way to convey that public key safely to prevent active attacks.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Mechanism

## External Encryption Key Derivation

Groups using this extension derive a dedicated HPKE {{!RFC9180}} key pair from the epoch secret for encrypting external messages. This key pair is derived independently from the ratchet tree structure.

The external encryption key pair is derived as follows:

~~~
external_encryption_secret =
    ExpandWithLabel(epoch_secret, "external encryption", "", KDF.Nh)

(external_encryption_private_key, external_encryption_public_key) =
    DeriveKeyPair(external_encryption_secret)
~~~

Where:

- `epoch_secret` is the epoch secret from {{!RFC9420}}
- `ExpandWithLabel` is from {{!RFC9420}}
- `DeriveKeyPair` is from {{!RFC9180}}
- `KDF.Nh` is the output size of the hash function for the cipher suite

All group members in the current epoch can derive the same key pair from their shared epoch secret. The public key is made available to external senders via the `ExternalEncryptionInfo` structure ({{ext-info}}).

## Additional information shared in every commit {#ext-info}

Groups participating in this mechanism include a `root_private_signature_key` component (see {{Section 4.6 of !I-D.ietf-mls-extensions}}) in the GroupContext of type `RootPrivateSignature`, containing a unique random private signature key corresponding to the group's cipher suite.
Whenever a commit removes a member from a group, this component MUST be replaced with a new unique random private signature key.

Members sending a commit need to calculate the future `epoch_secret`, `external_encryption_secret`, and `external_encryption_public_key` for the new epoch that would result if the commit is accepted.
The commit sender includes one additional Additional Authentication Data (AAD) component (see {{Section 4.9 of !I-D.ietf-mls-extensions}}) of type `ExternalEncryptionInfo` in every commit (including commits sent in a `PrivateExternalMessage`).
The `ExternalEncryptionInfo` includes the `external_encryption_public_key` for the future epoch.

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
    HPKEPublicKey external_encryption_public_key;
    SignaturePublicKey root_public_signature_key;
} ExternalEncryptionInfoTBS;

struct {
    CipherSuite ciphersuite;
    HPKEPublicKey external_encryption_public_key;
    SignaturePublicKey root_public_signature_key;
    /* SignWithLabel(root_private_signature_key, */
    /*    "ExternalEncryptionInfoTBS", ExternalEncryptionInfoTBS) */
    opaque external_encryption_signature<V>;
} ExternalEncryptionInfo;
~~~

## Sending an external proposal or external commit to the group

A non-member client that wishes to send a message to the group, first constructs a `PublicMessage` called `external_message_plaintext`.
The `PrivateExternalMessage` wire format wraps that `external_message_plaintext` by encrypting it to the `external_encryption_public_key`.

~~~ tls
/*  PublicMessage.content.sender.sender_type != member  */
PublicMessage external_message_plaintext;

encrypted_public_message = EncryptWithLabel(external_encryption_public_key,
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

To decrypt the message, members first derive the external encryption key pair from their current epoch secret:

~~~ tls
/* Derive the external encryption key pair from epoch_secret */
external_encryption_secret =
    ExpandWithLabel(epoch_secret, "external encryption", "", KDF.Nh)

(external_encryption_private_key, external_encryption_public_key) =
    DeriveKeyPair(external_encryption_secret)

/* Decrypt the external message */
external_message_plaintext = DecryptWithLabel(
    external_encryption_private_key,
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

An established MLS group which only exchanges handshakes using MLS PrivateMessage enjoys a high level of privacy for its members.
The GroupContext and the ratchet tree, including the contents of the credentials in MLS leaf nodes is not visible to outsiders nor to the DS.
However, during the process of joining, private information is often leaked to the DS.
This mechanism focuses on improving the privacy for the external joining mechanisms.

There are three mechanisms for potential new members to join an MLS group: an existing member gets a KeyPackage (KP) for the new member and commits an Add proposal with the KP; the joiner sends an external proposal asking to join the group that needs to be committed by an existing member; or the joiner fetches the GroupInfo of the group (usually from the DS) and sends an external commit.
In the base MLS protocol {{!RFC9420}}, an external join or external commit needs to be sent as an MLS PublicMessage, which greatly reduces the privacy of the group.

## Security of External Proposals

External Add proposals in {{!RFC9420}} are sent using an MLS PublicMessage, which is integrity protected but reveals the public signature key, MLS capabilities, MLS credential to the DS, and KeyPackageRef (used to correlate Welcome messages).
If a public key representing the entire target MLS group is available, the external proposer can encrypt this information to all group members without revealing it to the DS.
The external proposer needs a way to get this public key and not the key of an active attacker, and the DS and members need a reasonable authorization and rate limiting mechanisms to prevent from being overwhelmed by such encrypted requests.

The `ExternalEncryptionInfo` defined in {{ext-info}} contains a per-group, per-epoch signature key shared by all members of the group
The `ExternalEncryptionInfo` could be posted in transparency ledger, shared as gossip, or additionally signed by a specific member.
The specific mechanism can be tailored to a specific application as needed.

Application protocols above the MLS layer would also need to provide authorization. For example, in the MIMI protocol {{?I-D.ietf-mimi-protocol}} this could be a join code. Other techniques such as using single or limited use pseudonymous tokens, privacy pass {{?RFC9576}}, or anonymous credit tokens {{?I-D.schlesinger-cfrg-act}} are all reasonable options.
The privacy of some of these techniques could also be reinforced by using Oblivious HTTP {{?RFC9458}}.

## Security of External Commits


## Security of KeyPackages


As long as KeyPackages are exchanged securely out of band
This extension extends privacy of the MLS GroupContext and ratchet tree


## Security of Welcomes



# IANA Considerations

TODO IANA


--- back
