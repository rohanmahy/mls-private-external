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
    organization: XMTP Labs
    email: chenani@outlook.com

normative:

informative:

--- abstract

MLS groups that use private handshakes lose member privacy when sending external proposals. This document addresses this shortcoming by encrypting external proposals using an HPKE public key derived from the epoch secret. It also provides a mechanism to share this key and protect it from tampering by a malicious intermediary.

--- middle

# Introduction

The MLS protocol {{!RFC9420}} was designed to support both a model where the Distribution Service (DS) sees the contents of MLS handshake messages and often assumes a policy enforcement role, and a model where the DS is merely responsible for forwarding handshake messages and possibly enforcing ordering of messages.
In the first model clients send every handshake as a PublicMessage (or a SemiPrivateMessage {{?I-D.mahy-mls-semiprivatemessage}}), whereas in the second model the clients send in-group handshakes as a PrivateMessage.
As of this writing there are non-trivial commercial deployments using both the PublicMessage model (ex: Cisco, Amazon, Ring Central, Wire) and the PrivateMessage model (ex: XMTP, Germ).

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

Groups using this extension derive a dedicated HPKE {{!RFC9180}} key pair from the next epoch secret for encrypting external messages. 
When creating a provisional commit, the committer first computes the epoch secret that will result from processing the provisional commit, then derives the external encryption key from that epoch secret.

This ensures that removed members cannot decrypt external messages, as they do not have access to the next epoch secret.

### Computing the Next Epoch Secret

When a member creates a commit, they compute the next epoch secret before sending the commit, following the key schedule defined in {{!RFC9420, Section 8}}.

The next epoch secret is derived through the standard MLS key schedule: the `commit_secret` (from the commit's UpdatePath) and the current epoch's `init_secret` produce the `joiner_secret`, which is combined with any PSK secrets to produce the `epoch_secret` for the new epoch. This document refers to this value as `epoch_secret_next`.

### Deriving the External Encryption Key

The external encryption key is then derived from the next epoch secret:

~~~
external_encryption_secret =
    ExpandWithLabel(epoch_secret_next, "external encryption", "", KDF.Nh)

(external_encryption_private_key, external_encryption_public_key) =
    KEM.DeriveKeyPair(external_encryption_secret)
~~~

Where:

- `epoch_secret_next` is the epoch secret computed for the next epoch
- `ExpandWithLabel` is defined in {{!RFC9420, Section 8}}
- `KEM.DeriveKeyPair` is defined in {{!RFC9180, Section 4}}
- `KDF.Nh` is the size of an output from `KDF.Extract` for the cipher suite, as defined in {{!RFC9420, Section 8}}

The `epoch` field in `ExternalEncryptionInfo` MUST be set to `current_epoch + 1`.

The public key is made available to external senders via the `ExternalEncryptionInfo` structure ({{ext-info}}). All group members in the new epoch can derive the same key pair from their shared next epoch secret.

## Additional information shared in every commit {#ext-info}

Groups participating in this mechanism MUST include a `root_private_signature_key` component (see {{Section 4.6 of !I-D.ietf-mls-extensions}}) in the GroupContext of type `RootPrivateSignature`, containing a unique random private signature key corresponding to the group's cipher suite.
Whenever a commit removes a member from a group, this component MUST be replaced with a new unique random private signature key.

Members sending a commit need to calculate the future `epoch_secret`, `external_encryption_secret`, and `external_encryption_public_key` for the new epoch that would result if the commit is accepted.
The commit sender MUST include one additional Additional Authentication Data (AAD) component (see {{Section 4.9 of !I-D.ietf-mls-extensions}}) of type `ExternalEncryptionInfo` in every commit (including commits sent in a `PrivateExternalMessage`).
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

The `epoch` field in `ExternalEncryptionInfoTBS` indicates the epoch for which the external encryption key is valid. Since the key is derived from the next epoch secret, this field MUST be set to `current_epoch + 1`, where `current_epoch` is the epoch number at the time the commit is created. Once the commit is processed and the group advances to the new epoch, the `epoch` field will match the group's current epoch.

## Sending an external proposal or external commit to the group

A non-member client that wishes to send a message to the group first obtains the `ExternalEncryptionInfo` from the group's most recent commit. Before using the `external_encryption_public_key`, the external sender MUST verify the `external_encryption_signature` by computing `VerifyWithLabel` using the embedded `root_public_signature_key` and the label `"ExternalEncryptionInfoTBS"` over the reconstructed `ExternalEncryptionInfoTBS`. If verification fails, the `ExternalEncryptionInfo` MUST be rejected.

The external sender then constructs a `PublicMessage` called `external_message_plaintext`. The `sender_type` in the inner `PublicMessage` MUST NOT be `member`, since this mechanism is for external senders only.

The `PrivateExternalMessage` wire format wraps that `external_message_plaintext` by encrypting it to the `external_encryption_public_key`.

The `PrivateExternalMessageContext` is an empty struct, serialized to a zero-length byte string:

~~~ tls
struct {
} PrivateExternalMessageContext;

struct {
    opaque group_id<V>;
    uint64 epoch;
    ContentType content_type;
    opaque authenticated_data<V>;
    HPKECiphertext encrypted_public_message;
} PrivateExternalMessage;
~~~

The encryption and message construction are as follows:

~~~
encrypted_public_message = EncryptWithLabel(external_encryption_public_key,
    "PrivateExternalMessageContent", PrivateExternalMessageContext,
    external_message_plaintext)

PrivateExternalMessage.authenticated_data =
   external_message_plaintext.content.authenticated_data
~~~

The `PrivateExternalMessage` is sent as a new variant of `MLSMessage`:

~~~ tls
struct {
    ProtocolVersion version = mls10;
    WireFormat wire_format;
    select (MLSMessage.wire_format) {
        case mls_public_message:
            PublicMessage public_message;
        case mls_private_message:
            PrivateMessage private_message;
        case mls_private_external_message:
            PrivateExternalMessage private_external_message;
    };
} MLSMessage;
~~~

## Decryption and verification by members

Members receiving a `PrivateExternalMessage` MUST verify that the `group_id` matches a known group and that the `epoch` field matches their current epoch. If either check fails, the message MUST be rejected.

To decrypt the message, members derive the external encryption key pair from their current epoch secret. Since the `ExternalEncryptionInfo` was created using the next epoch secret (which is now the members' current epoch secret), the derivation will produce the correct key:

~~~
external_encryption_secret =
    ExpandWithLabel(epoch_secret, "external encryption", "", KDF.Nh)

(external_encryption_private_key, external_encryption_public_key) =
    KEM.DeriveKeyPair(external_encryption_secret)

external_message_plaintext = DecryptWithLabel(
    external_encryption_private_key,
    "PrivateExternalMessageContent", PrivateExternalMessageContext,
    encrypted_public_message.kem_output,
    encrypted_public_message.ciphertext)
~~~

If decryption fails, the message MUST be rejected.

Members MUST then verify that the following values in the `PrivateExternalMessage` match their corresponding field in the `external_message_plaintext.content`:

- `group_id`,
- `epoch`,
- `content_type`, and
- `authenticated_data`

If any of these checks fail, the message MUST be rejected.

Members MUST also verify that the `sender_type` in the decrypted `external_message_plaintext` is not `member`. Messages from group members MUST NOT be wrapped in a `PrivateExternalMessage`.

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

TODO

## Security of KeyPackages and Welcomes

In the classical usage of MLS, a member of a group fetches a KeyPackage, commits an Add proposal containing that KeyPackage, the sends a Welcome to the new member.
Both the returned KeyPackage and the query for it could reveal a lot of private information.
In order to forward a Welcome message to the correct recipient, the DS needs to be able to associate the `KeyPackageRef` with some resource that eventually delivers to the appropriate client.

TODO add more.

# IANA Considerations

This document registers two new MLS Component Types in the Specification Required range.


## root_private_signature_key MLS Component Type

- Value: TBD (suggested value 0x000A)
- Name: root_private_signature_key
- Where: GC
- Recommended: Y
- Reference: RFC XXXX

## external_encryption_public_key MLS Component Type

- Value: TBD (suggested value 0x000B)
- Name: external_encryption_public_key
- Where: AD
- Recommended: Y
- Reference: RFC XXXX

## PrivateExternalMessage MLS WireFormat

TODO

--- back
