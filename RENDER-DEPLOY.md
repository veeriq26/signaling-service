# Render signaling test deployment

This deploys only the authenticated WebSocket signaling service. Render
terminates public TLS and forwards the request to the container; the service
listens on Render's `PORT` using HTTP/WebSocket internally. Public clients
must still use `wss://<service>.onrender.com/signal`.

Render does **not** host the coturn UDP relay in this setup. This is suitable
for testing signaling and direct WebRTC connectivity, not a guarantee of
cross-NAT connectivity. A separately operated TURN service is still required
when direct ICE cannot connect. Do not add a TURN secret unless a real,
authorized coturn service uses that exact REST secret.

## Before deploying

The repository on GitHub must contain this service's `Cargo.toml`,
`Cargo.lock`, `src/`, `.gitignore`, `Dockerfile`, and `render.yaml`. Do not
push `target/`, TLS certificates/private keys, `.env` files, or secrets.
Keep the GitHub repository private unless you intentionally want the source
public.

This clone's GitHub `origin` may be an empty repository until the source files
are committed and pushed. Check the repository and branch in the dashboard
before connecting Render.

## Create the Render service

1. In Render, use **New > Blueprint** (not a static site). Connect the GitHub
   repository that contains this folder and select the branch with
   `render.yaml`.
2. Review the Blueprint changes. It should create one free web service named
   `veeriq-signaling`; approve the creation only if the settings match this
   file. Render builds the Dockerfile and uses `/healthz` for its health check.
3. Wait for the first deploy to finish. The Render service URL should look like
   `https://veeriq-signaling.onrender.com`. Set the app's endpoint to
   `wss://veeriq-signaling.onrender.com/signal` (use the actual generated
   service name).
4. Open `https://<service>.onrender.com/healthz` in a browser. A `204` response
   indicates the process is reachable; it does not authenticate a device or
   verify WebRTC connectivity.
5. Connect the desktop client and confirm device authentication. Test
   Allow/Reject and session cleanup on two devices. If there is no STUN/TURN
   server, direct connectivity may fail on separate networks.

## Free-plan limits and security

Render's free web services can spin down after inactivity and may have
availability, resource, and usage limits. Check the current
[Render free-instance limits](https://render.com/docs/free) before relying on
the service. A sleeping or replaced signaling instance disconnects clients;
the client must reconnect, and the app intentionally requires a new host
approval for a new screen session. This is a test deployment, not a reliable
always-on rendezvous service.

The server keeps active signaling connections in process memory. Do not scale
this service to multiple instances: Render can route each WebSocket connection
to a different instance, while this prototype does not share connection state.
The free plan uses one instance by default.

Do not place TLS private keys in Render environment variables for this proxy
mode; Render provides public HTTPS/WSS at the edge. `VEERIQ_SIGNAL_PROXY_TLS`
must remain explicitly set to `true`, and `PORT` is assigned by Render. Do
not expose this plain internal listener outside Render's service networking.
The server still requires the desktop device-key challenge authentication
before accepting signaling messages.

Do not add `VEERIQ_ICE_URLS` with a TURN URL unless the corresponding TURN
service and shared secret are configured and authorized. The public signaling
service distributes short-lived credentials only; it does not relay video.
