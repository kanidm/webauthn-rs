# webauthn-rs cable-tunnel-server

**Warning:** This is still a work in progress, and not yet fully implemented.

However, you can run a single-task tunnel service with the `backend` alone:
[see `./backend/README.md` for instructions][0].

[0]: ./backend/README.md

## Background

To facilitate two-way communication between an initiator (browser) and
authenticator (mobile phone), caBLE uses a WebSocket tunnel server. There are
tunnel servers run by Apple (`cable.auth.com`) and Google (`cable.ua5v.com`),
and a facility to procedurally generate new tunnel server domain names (see
`get_domain()` in `webauthn-authenticator-rs/src/cable/tunnel.rs`).

As far as the tunnel server is concerned, what happens is:

1. The authenticator and initator choose a 16 byte tunnel ID.

2. The authenticator connects to a tunnel server of its choosing, using HTTPS.

3. The authenticator makes a WebSocket request to `/cable/new/${TUNNEL_ID}`.

4. The tunnel server responds with a WebSocket handshake, and includes a 3 byte
   routing ID in the HTTP response headers to indicate which task is serving
   the request.

5. The authenticator transmits the tunnel server ID and routing ID as as an
   encrypted Bluetooth Low Energy advertisement to the initiator.

6. The initiator decrypts the advertisement, and connects to the tunnel server
   using HTTPS.

7. The initiator makes a WebSocket request to
   `/cable/connect/${ROUTING_ID}/${TUNNEL_ID}`.

8. The tunnel server responds with a WebSocket handshake.

9. The tunnel server relays WebSocket messages between the authenticator and
   initiator.

The initiator starts a Noise channel with the authenticator for further
communication such that the tunnel server cannot read their communications, and
then does registration or authentication using the FIDO 2 protocol.

Aside from implementing some basic request filtering, message limits and session
limits, the tunnel server implementations are very simple. The tunnel server
itself does not need to concern itself with the minutae of the Noise protocol -
it only needs to pass binary messages across the tunnel verbatim.

## Design

`cable-tunnel-server` consists of three parts:

* `backend`: serving binary which passes messages between the authenticator and
  initiator on a known tunnel ID.

* `frontend`: serving binary which routes requests to a `backend` task based on
  the routing ID (for `connect` / initiator requests), or some other load
  balancing algorithm (for `new` / authenticator requests).

* `common`: contains all the web server and caBLE boilerplate which is shared
  between the `backend` and `frontend` binaries.

### Backend

It should be possible to run the `backend` without a `frontend` – in this case
the routing ID will be ignored, and all tunnels exist inside of a single serving
task.

### Frontend

**Warning:** The `frontend` is not yet fully implemented, and does not yet do
everything described here. This would be necessary for a larger scale deployment
of a caBLE tunnel server.

The `frontend` needs to do some basic request processing (for routing) before
handing off the connection to a `backend`:

* For connecting to existing tunnels, the `frontend` needs to connect to
  arbitrary `backend` tasks *in any location*.

* For establishing new tunnels, the `frontend` should prefer to route to "local"
  `backend` tasks, taking into account backend availability and load balancing.

This will probably need some distributed lock service to allocate the routing
IDs.

While it would be possible to route based on the tunnel ID *alone*, this would
make tunnel create / fetch operations global.

## Example session

```
2023-03-20T07:53:05.004480Z  INFO cable_tunnel_server_backend: Starting server on 127.0.0.1:8081
2023-03-20T07:53:24.369165Z  INFO cable_tunnel_server_backend: 127.0.0.1:51407: GET /cable/new/73D229226F1F1C015787C2E0E8988644
2023-03-20T07:53:24.370187Z  INFO cable_tunnel_server_backend: 127.0.0.1:51407: WebSocket connected
2023-03-20T07:53:30.042372Z  INFO cable_tunnel_server_backend: 127.0.0.1:51410: GET /cable/connect/C0FFEE/73D229226F1F1C015787C2E0E8988644
2023-03-20T07:53:30.042913Z  INFO cable_tunnel_server_backend: 127.0.0.1:51410: WebSocket connected
2023-03-20T07:53:30.044039Z  INFO cable_tunnel_server_backend: 127.0.0.1:51410: message 1: 0411ab63121a293777f5698cda2cd6772b218150cf5ffe782904a6dbf3939143283566232a8f4c5f3132f530aeb7358738198ea909ef012c908a8d1c4a3f4a9b728cb1d208b03096fceb093dae867538c3
2023-03-20T07:53:30.073778Z  INFO cable_tunnel_server_backend: 127.0.0.1:51407: message 1: 04cacad2beffb7ff816a9d19b0ea6d3189ec6576daaf8eff8652a724b1a7ada143b7aeb9374340150bc3344680711371a62744dcca6e89aa135ff74e40f7ef440c23275d7925d862bef55576102afed68e
2023-03-20T07:53:30.074386Z  INFO cable_tunnel_server_backend: 127.0.0.1:51407: message 2: 25cc353aaa7fae0e0cf51aa8d41fa3f1edf47fcd0d8b0b2885c85b957e5cc8f25aea42481cd8591b5fd716ec0fa4a7a35a0bd80f9232019132db5ba9a0cbd4c8602d95927a6ab0f86b16c8c2265a9c01ee1b9864ce3ec03e42a52d146fdc157eff98a051ef6e8e14bf528b2cc43a2166
2023-03-20T07:53:30.078271Z  INFO cable_tunnel_server_backend: 127.0.0.1:51410: message 2: 7e8846ad02d03157a647d999116936563f7c641b14eb31dfa0edb1a4555c7c956e431646b065dbbe36beb32a5d6b4b3e832c74cdd194905c398e5339e690740f8febda6c1331985c3f3d48f9682f6035117283710f0acc0f18e63dde8698a78d59430c7d5e4259a0e66c5dd4351bb6a121a52ad4035bdffbcbf07d7b7b0bf1177b4e83708a20140c4c3fa03b4455bb6f31a2712acdaa2136d55d1b201a06e813e2417d2fef91bf222988599ff1d75a16f8472fb0194a03e985832c602a925248c8d196fa265bfa63f3a5b82428221e69d5884cb39c30367ec6c97243ae3af2b4ab6a0a3c55a07bf6f191d0e051161106
2023-03-20T07:53:30.081330Z  INFO cable_tunnel_server_backend: 127.0.0.1:51407: message 3: 99d498868db37726c51157d15079c71e7d565db8054820b545b0d9744eeffae16dbf21b7ceea54ec02d7a54c1776156332aefec9be90e0e4d8a8e8642a1f409f4cca6bc02ac3218b369e7460e32f60da73c4b31452874941d917759a31a931c25976a09c2c6e9d3acc2d2e678b712317fa06dde40fd4f71893a70983e67d3da8897788f3afeb74f0ce851c7eb1ae07e5de3fb30ef88b6779e98c2c4e3f693a80d0ec73b99057d9ed01260a5940394f849d80b79da57d98b59bc47d73742f040c53bf9a5d5bdf13a62750776b3c05736cb4c592bd2e4ee3dcef3ade55e6c2c812603c05545a069efb0045ca464a81dc0eb2cecb538137fe48f8f9d5b8bcf7f547ea5af9519af52148962aab333c8ef206d3bc22605fa15fea44bad411ad3cf3cb649689651621b06baa84b9b065496c7955ff25a3a01f4655d9b83baa0e2197f5782e12fc0004900268cd8f77ceaddba5df7ac949f68b65dd9493ca33799ec468c17ccbe6bba893974ef6275e7038730c684b19ac79922cdde5ee4bb8890ac25edf4943f4d3768e47fe076bc41832c70519b6af0befb5a128e84e63c9b6b62e794f1eb6d0f1ba45be840657a1a22a76149ea69d44f17b30ba6dd0616eb65cc96cac378308ee264c193449efad58a72ecd3cd4fbf4eeeb846d76f10ec049fb0c9cac8a2a5134c2fc96370202cfbd28466709a32d936e6c2f00d6824378ee579ef11fa67640d8c3e224ceb1f42a941fd79c85466b08d331e699f1891a143c5488031e32c253bf8e6a757600a6b917251f35cc72456bf2944585bcce4e9856664179ab4a99402a7e97129a6bb51a715dccfc03f277f05ae1e1a387832001765ba9b1680a41a63fce8360bd3fdc43a120e14f3f7a9e7debcb0d4490fd3ade1e1152c363fce171dd89d1b6b913797a92928eb20612c4a8d5d49048b27c7179719dc5ceaa27a68a8f87d7c48011b88bfa11925305f7dcd76cd42367114312dced722f3e78f05fc2639e4af00ae65abdc515bab98b8c5d725acd4794806f95dc95c05d707dae599f3ff77176c401a9355061ab25276cfdae083c73149de469b0ac4e08eac646ecd3e7e1a63b3cbbccaa0f78973264d779d67b72b07f9d35429b3acd37556d53fa75afe997b92a352efb245fc3a39200e7b4a08252381d76d3295d440b331e84f229f549455687075634cb09105c576570986b7cdedc483b0c845f79b610224c7951078120445ceff7e7edac4320
2023-03-20T07:53:30.084185Z  INFO cable_tunnel_server_backend: 127.0.0.1:51407: message 4: 2ba2d22fddadce33b856efe279d9a2f7b8ebdc55701b7999ab4797fa6efad09d4a81dc7699319addfe449775eec3d895
2023-03-20T07:53:30.084913Z  INFO cable_tunnel_server_backend: 127.0.0.1:51407: message 5: fae348233c59d1cdfa291a444b09110aa0e56420252623d158fa121e3b53994f7afa4d99e3e76ae331851f5cc33a94f1
2023-03-20T07:53:30.085495Z  INFO cable_tunnel_server_backend: 127.0.0.1:51407: closing connection
2023-03-20T07:53:30.085876Z  INFO cable_tunnel_server_backend: 127.0.0.1:51407: finishing
2023-03-20T07:53:30.086480Z  INFO cable_tunnel_server_backend: 127.0.0.1:51410: finishing
2023-03-20T07:54:25.056208Z  INFO cable_tunnel_server_backend: 127.0.0.1:51416: GET /cable/new/8B0D4410FA0EC04FA4715F40EAC167F2
2023-03-20T07:54:25.056663Z  INFO cable_tunnel_server_backend: 127.0.0.1:51416: WebSocket connected
2023-03-20T07:54:59.555054Z  INFO cable_tunnel_server_backend: 127.0.0.1:51420: GET /cable/connect/C0FFEE/8B0D4410FA0EC04FA4715F40EAC167F2
2023-03-20T07:54:59.555526Z  INFO cable_tunnel_server_backend: 127.0.0.1:51420: WebSocket connected
2023-03-20T07:54:59.556531Z  INFO cable_tunnel_server_backend: 127.0.0.1:51420: message 1: 04ca9680e8ab62e3bc09c07bc72a8f14f93d7901621c750d1d9cbdeecf78d4896c75aa97297aaf1adbd1e93b88948e3d6bbef3b864d7a332ce5cc002030b834a8270be182c34599b68f0d09e1146afb996
2023-03-20T07:54:59.590804Z  INFO cable_tunnel_server_backend: 127.0.0.1:51416: message 1: 04600dfc2639e37772fecc09a9418ea1b4b1f4ba2e6323378a7921a71332e876f3a71ded5ce98eba484e640aa2cdb8295713a1970657e986af65e8375ab6e16a6bd4d41d7e6806d9a999f31788c93bae79
2023-03-20T07:54:59.591482Z  INFO cable_tunnel_server_backend: 127.0.0.1:51416: message 2: ddef12416a7151b45fd799996be004b5058049fd0010d52b2b4ed31981b5cb45ecb5e770f11ebbf2b5e38589bc77c7d1a7ef27488e38d61b962667d024a9e01b05276bb05e47d517dd6f581498ab4952f5970259d532aed06cdcb87a39d7bdf445d8e36544d9690c24972300e8553969
2023-03-20T07:54:59.594769Z  INFO cable_tunnel_server_backend: 127.0.0.1:51420: message 2: f050d7960ccb002032fedcd935f85d5b9b3e983638be07cc87bcc41a0dd97bb143ec9e32949a32e6d83b45b83186a65d008da1742c615010da9e40f6bfb722d3cc1be0bd4e09e29725bdcf312a18881a8eca63deb5f01f73c71d0af3e1f5269943cc4be30c9b6eb6f51b710da8df4d47d7f15d3bebd25a47b7de1f7fa5ca092f5ae5c87b081492b327db0af91a9b57f6
2023-03-20T07:54:59.597070Z  INFO cable_tunnel_server_backend: 127.0.0.1:51416: message 3: 8f0650dda989f302932bea995fc8a1a2c7e07706708e640823c6e42d2df9e62557935b12ee97f31cd2674b31669ac9d6975b56b3c6bce1cbb1fd669ff9ffa68ef41e44b7036118131b630139a295a458b7334bde24b8907b2c501c29e09f0a1470c536ad8eb2266d4ef373c3135648d9868e3f0abaeb15e3435bbe6ac0204aba50a3b9a99c01fd3ad7847b8540b3a36f7900b454157cfe236277e373301accdafe3200c6b129a9ac586235f31b24dd49d7bea8f2edaa72e1742fb64e64de4df4afe4db734b80f2ffe10887cc001b25f2
2023-03-20T07:54:59.598159Z  INFO cable_tunnel_server_backend: 127.0.0.1:51416: message 4: b094e43818a694f21ddbf4fa188a5286c189a8ce9f921e17c03bd2ffecc274bc0836c828b892d77fd6a16e49ecbdb692
2023-03-20T07:54:59.598593Z  INFO cable_tunnel_server_backend: 127.0.0.1:51416: message 5: 3647d8bddb3da1a4aa7a092b7c40cc1d1ae5a7424a20f711bd404c034f54d6c214b7e8830d762d4766f6213e03640b10
2023-03-20T07:54:59.599062Z  INFO cable_tunnel_server_backend: 127.0.0.1:51416: closing connection
2023-03-20T07:54:59.599358Z  INFO cable_tunnel_server_backend: 127.0.0.1:51416: finishing
2023-03-20T07:54:59.599995Z  INFO cable_tunnel_server_backend: 127.0.0.1:51420: finishing
```

Safari:

```
Request { method: GET, uri: /cable/connect/000000/AF2F010B02F4013B4E0393870AE2D9BC, version: HTTP/1.1, headers: {"host": "cable.my4kstlhndi4c.net", "user-agent": "com.apple.AuthenticationServicesCore.AuthenticationServicesAgent/18614.4.6.1.6 CFNetwork/1404.0.5 Darwin/22.3.0", "sec-websocket-protocol": "fido.cable", "sec-websocket-key": "Zz2jOa5v7DBnA/yFGJc/0A==", "sec-websocket-version": "13", "upgrade": "websocket", "accept": "*/*", "sec-websocket-extensions": "permessage-deflate", "accept-language": "en-AU,en;q=0.9", "accept-encoding": "gzip, deflate", "connection": "Upgrade"}, body: Body(Empty) }
```
