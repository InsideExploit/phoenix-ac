# phoenix-ac

## Premessa

<table border="1" width="100%" cellpadding="16" cellspacing="0">
  <tr>
    <td>
      <p><strong>Perché ho messo online le sorgenti (self-leak)</strong></p>
      <p>Il leak è <strong>volontario</strong>. Sono uscito da phoenix-ac / Enveart e ho pubblicato il repo perché non resti solo la versione raccontata in <strong>live</strong> o su Discord.</p>
      <p>Dietro anti-cheat e server c'è stato un disastro di <strong>management</strong>: <strong>promesse non mantenute</strong>, <strong>pagamenti mancati</strong>, risposte che <strong>evitavano</strong> il punto invece di risolvere. In <strong>live su Twitch</strong>, e da <strong>altre persone</strong>, sono uscite affermazioni che <strong>non tornavano</strong> con ciò che c'era davvero, che <strong>non sono mai arrivate</strong>, o che erano <strong>semplicemente false</strong>.</p>
      <p>Ho <strong>lasciato il progetto</strong> e ho <strong>leakkato tutto</strong> qui. Il resto del README descrive la <strong>struttura</strong> del prodotto <strong>com'era</strong> quando ho chiuso: architettura, cartelle e flussi, così si può verificare sui fatti e non solo a parole.</p>
      <p><strong>Sull'AI:</strong> non vendo la favola che Claude abbia scritto tutto da solo. Su <strong>v1/v2</strong> il modello pesava troppo e l'architettura ne ha risentito. Su <strong>v3 e Latest</strong> ho usato Claude anche per generare codice, sì, ma <strong>struttura</strong>, <strong>architettura</strong> e <strong>decisioni</strong> le ho messe io. Stesso tool, modo diverso di lavorarci.</p>
      <p><em>(Per chiarezza: anche tutto il README l'ho messo su in fretta con Claude, non solo questo box; contenuti e motivazioni restano miei. 😄)</em></p>
    </td>
  </tr>
</table>

---

FiveM anti-cheat: Windows agent (+ optional kernel driver), Node backend, Next.js site, FiveM Lua resource. **This git repository contains all product lines** (v1 through Latest) as top-level folders. **Run new deployments from:** `Phoenix-v3-Uhm-Latest/` (server) + `Phoenix-v3-Uhm/` (Windows client).

## History

**AI disclosure:** not "Claude wrote the whole repo." **v1/v2** leaned on the model with weak architecture (v1 especially: throwing output at Claude without real design). **v3 and Latest are mine:** I authored them using Claude as a tool, but under **my own logic**, **my own knowledge**, and explicit structure (review, constraints, net layout). Same assistant, different process. That still does not make the design great; it explains why v3/Latest are not the same thing as v1.

All folders stay **in this repo** for history. Do not deploy v1/v2. Use v3-Uhm for the client and Latest for the server.

| Directory | Ver. | Use now | How it was made / verdict |
| --- | --- | --- | --- |
| Phoenix-v1-Hydro | v1 | no | Claude + no competence: incompetent architecture, bad netcode, monolithic client C++. |
| Phoenix-v2-Hydro-Refactor-Uhm | v2 | no | Claude with some skill, but rushed refactor from v1 source (time). Still sucks; inherited junk. |
| Phoenix-v3-Uhm | v3 | client | **My work.** Full stack (agent, driver, updater, script). Claude assisted; architecture and decisions are personal. |
| Phoenix-v3-Uhm-Latest | Latest | server | **My work.** Control plane rewrite/consolidation. Claude assisted; personal logic and skills. Works; mediocre netcode; should be rewritten. Least bad. |

```mermaid
flowchart TB
  subgraph older [Older lines still in repo]
    V1[Phoenix-v1-Hydro]
    V2[Phoenix-v2-Hydro-Refactor-Uhm]
  end

  subgraph v3 [Phoenix-v3-Uhm]
    AG[PhoenixAgent]
    DRV[PhoenixDrv]
    UPD[PhoenixUpdater]
    LUA[PhoenixScript]
    OLD[legacy backend/site copies]
  end

  subgraph latest [Phoenix-v3-Uhm-Latest operational server]
    BE[backend/]
    WEB[website/]
    SQL[sql/]
  end

  AG --> BE
  UPD --> BE
  LUA --> WEB
  LUA --> BE
  WEB --> BE
  WEB --> SQL
  BE --> SQL
```

Latest is maintainership **by me** after v1/v2/v3 chaos. Read `AgentSession`, count PAC1 + PAC1 update + PHX + HTTP, and it is clear why the codebase **generally sucks** even when it runs. One net stack and a rewrite would be the sane next step.

## System overview

```mermaid
flowchart TB
  subgraph pc [Player PC]
    GM[FiveM client]
    AGENT[Phoenix Agent]
    DRIVER[Phoenix Driver optional]
    UPDATER[Phoenix Updater]
    GM --- AGENT
    AGENT --- DRIVER
    UPDATER --> AGENT
  end

  subgraph infra [Server]
    SITE[Next.js website :3000]
    PHX[PHX wire gateway :37241]
    BACKEND[Backend Node]
    P15[TCP Agent :27015]
    P16[HTTP :27016]
    P17[TCP Update :27017]
    DB[(MySQL)]
    DISCORD[Discord webhooks]
    BACKEND --- P15
    BACKEND --- P16
    BACKEND --- P17
    BACKEND --- DB
    BACKEND --- DISCORD
    SITE --- DB
    SITE --- PHX
    SITE -->|Bearer PAC_HTTP_TOKEN| P16
  end

  subgraph fx [FiveM host]
    RES[PhoenixScript]
  end

  AGENT <-->|PAC1| P15
  UPDATER <-->|PAC1 update| P17
  AGENT -.->|legacy optional| PHX
  RES -->|HTTPS phoenix-ac API| SITE
  RES -->|HTTP slot session| P16
  STAFF[Staff browser] --> SITE
```

## Latest backend layout

```mermaid
flowchart LR
  IDX[index.ts] --> NET[net/server.ts]
  IDX --> HTTP[http/fivem.ts]
  IDX --> UPD[updates/server.ts]
  IDX --> DBM[db/migrate + pool]
  IDX --> ART[updates/artifacts watcher]

  NET --> SESS[net/session.ts]
  SESS --> REG[net/registry.ts]
  SESS --> PROTO[proto/packet crypto bodies opcodes]
  HTTP --> REG
  SESS --> DBM
  SESS --> WH[discord/webhook.ts]
```

## Website layout

```mermaid
flowchart LR
  INST[instrumentation.ts] --> GW[tcp_gateway.ts]
  GW --> WHND[wire_handlers.ts]
  WHND --> WIRE[wire.ts veil.ts]

  APP[app/api routes] --> POOL[database pool]
  APP --> CFG[core/config.ts]
  APP -->|proxy| HTTPBE[Backend :27016]

  DASH[dashboard_client.tsx] --> APP
  PUB[landing auth download] --> APP
```

## Backend boot sequence

```mermaid
sequenceDiagram
  participant M as index.ts
  participant DB as MySQL
  participant A as Agent TCP 27015
  participant H as HTTP 27016
  participant U as Update TCP 27017
  participant W as Webhooks

  M->>DB: ping + migrate
  M->>A: startServer
  M->>H: startHttpServer
  M->>U: startUpdateServer
  M->>W: pingAllWebhooks optional
```

## Usage

1. Apply `Phoenix-v3-Uhm-Latest/backend/sql/schema.sql` or let backend migrate on boot.
2. Configure `backend/.env` and `website/.env.local` (never commit secrets).
3. Run backend: `cd Phoenix-v3-Uhm-Latest/backend && npm ci && npm run build && node dist/index.js`
4. Run website: `cd Phoenix-v3-Uhm-Latest/website && npm ci && npm run build && npm start`
5. Point `BACKEND_URL` at HTTP `:27016` with `PAC_HTTP_TOKEN`.
6. Build agent/driver/updater from `Phoenix-v3-Uhm/` (Release x64) and place artifacts per config.

## PAC1 agent session

```mermaid
stateDiagram-v2
  [*] --> awaiting_hello: TCP accept
  awaiting_hello --> awaiting_auth: ClientHello + keys
  awaiting_auth --> ready: Authenticate OK
  awaiting_auth --> closed: ban HWID version mode
  ready --> ready: Heartbeat Detection AltAccounts RPC
  ready --> closed: timeout kick shutdown
```

```mermaid
sequenceDiagram
  participant S as Backend AgentSession
  participant C as Agent

  S->>C: ServerHello + serverNonce
  C->>S: ClientHello + clientNonce
  Note over S,C: deriveSessionKeys from PAC_PSK_HEX
  C->>S: Authenticate steam HWID version optional PNG
  S->>S: players sessions registry
  S->>C: AuthResult
  loop ready
    S->>C: HeartbeatPing
    C->>S: HeartbeatPong
    C->>S: Detection optional
  end
```

Magic `0x50414331`, version `0x0001`. Handshake frames cleartext; then encrypted AES+HMAC with replay window. Opcode list: `backend/src/proto/opcodes.ts`.

```mermaid
flowchart TB
  subgraph rpc [On-demand RPC from HTTP dashboard]
    H[fivem.ts] --> R[registry LiveAgent]
    R --> SE[AgentSession]
    SE --> OP[Screenshot SysInfo PCI Minidumps Proc Scan Kick]
    OP --> C[Agent on 27015]
  end
```

## Update channel (27017)

```mermaid
sequenceDiagram
  participant U as Updater
  participant S as UpdateSession
  participant F as artifacts.ts

  U->>S: PAC1 handshake
  U->>S: identify steam + mode
  S->>U: UpdateManifest
  S->>U: UpdateChunkAgent chunks
  opt kernel bundle
    S->>U: UpdateChunkDriver
  end
  S->>U: UpdateEnd
  F-->>S: watched files on disk
```

## PHX legacy wire (website :37241)

Parallel stack inside Next.js (not PAC1). Magic `0x31584850`, AES-GCM + veil + HMAC. Opcodes: AuthCheck, Event, UpdateCheck, UpdateDownload (`website/lib/net/wire.ts`).

```mermaid
flowchart LR
  LEG[Legacy launcher or client] --> GW[tcp_gateway.ts]
  GW --> AH[handleAuthCheck]
  GW --> EV[handleEvent]
  GW --> UC[handleUpdateCheck]
  GW --> UD[handleUpdateDownload]
  AH --> MY[(players)]
  EV --> WH[webhooks + DB]
```

## Staff dashboard live action

```mermaid
sequenceDiagram
  participant B as Browser
  participant N as Next /api/players
  participant H as Backend HTTP
  participant R as registry
  participant A as Agent TCP

  B->>N: staff cookie session
  N->>H: Bearer PAC_HTTP_TOKEN
  H->>R: getLiveAgent steamHex
  R->>A: PAC1 request opcode
  A->>R: response chunks
  R->>H: JSON or file path
  H->>N: response
  N->>B: UI update
```

## FiveM + player flow

```mermaid
sequenceDiagram
  participant P as Player
  participant W as Website
  participant A as Agent
  participant B as Backend
  participant F as FiveM + PhoenixScript

  P->>W: PIN Steam download
  P->>A: start after updater
  A->>B: 27015 Authenticate
  P->>F: connect server
  F->>W: fingerprint server-check HTTPS
  F->>B: slot report session status HTTP
  loop in game
    B->>A: heartbeat
    A->>B: detection optional
  end
```

## HTTP surface (backend :27016)

Bearer `PAC_HTTP_TOKEN`. Router: `backend/src/http/fivem.ts`.

```mermaid
flowchart TB
  HTTP[fivem.ts]

  HTTP --> AGENT_EP[/v1/agent/* screenshot sysinfo pci minidumps dump proc scan/]
  HTTP --> ADM[/v1/admin/* kick ban suspend/]
  HTTP --> SESS[/v1/session/* status bulk/]
  HTTP --> SLOT[/v1/slot/report/]
  HTTP --> SHOT[/v1/screenshots/* static files/]
  HTTP --> MISC[/v1/steam/profile insecure-boot detection/]

  AGENT_EP --> REG[registry LiveAgent]
  REG --> PAC1[PAC1 on 27015]
```

## Website HTTP surface

```mermaid
flowchart TB
  subgraph public [Public and player]
    DL[download launcher update]
    AUTHP[auth steam discord]
  end

  subgraph fxapi [FiveM HTTPS]
    PAC[phoenix-ac server-check fingerprint kill-event event detection check crypto-status]
  end

  subgraph staff [Staff dashboard]
    PL[players moderation live tools]
    PIN[pins detections stats lookup evasion]
  end

  public --> MY[(MySQL)]
  fxapi --> MY
  staff --> MY
  staff -->|proxy| BE[Backend HTTP]
  PAC --> MY
```

Route files under `website/app/api/`.

## MySQL model

```mermaid
erDiagram
  players ||--o{ sessions : has
  players ||--o{ detections : has
  players ||--o{ pins : may_have
  players ||--o{ alt_accounts : has
  players ||--o{ player_fingerprints : has
  sessions ||--o{ detections : optional
  admins {
    string discord_id PK
    int sec_level
  }
  players {
    string steam_hex UK
    string hardware_id
    bool banned
    bool suspended
  }
  kills {
    string killer_steam_hex
    string victim_steam_hex
  }
  evasion_flags {
    string primary_hex
    string secondary_hex
  }
```

Schema file: `Phoenix-v3-Uhm-Latest/backend/sql/schema.sql`.

## Discord notifications

```mermaid
flowchart LR
  BE[backend webhook.ts] --> R[PAC_WH_REGISTRATIONS]
  BE --> A[PAC_WH_AUTH]
  BE --> S[PAC_WH_SESSIONS]
  BE --> H[PAC_WH_HWID_MISMATCH]
  BE --> DBL[PAC_WH_DETECTIONS_BLOCKING]
  BE --> DRP[PAC_WH_DETECTIONS_REPORT]
  BE --> DCH[PAC_WH_DETECTIONS_CHEATS]
  BE --> E[PAC_WH_ERRORS]

  SITE[website webhook.ts] --> SW[site PAC_WH_* login admin detection security]
```

## Windows agent (Phoenix-v3-Uhm)

Not in Latest repo; peers with backend PAC1.

```mermaid
flowchart TB
  MAIN[main.cpp service bootstrap]
  MAIN --> SESS[session net PAC1]
  MAIN --> WORK[worker orchestrator]

  WORK --> OVR[overlayscan]
  WORK --> MM[mmapscan]
  WORK --> IRP[irpscan]
  WORK --> DNS[dnsscan netmon]
  WORK --> SIG[fivemsig]
  WORK --> KW[keywatch]
  WORK --> DBG[antidbg ciguard guard]

  SESS --> CAP[capture single PNG]
  SESS --> MD[minidumps WinMinidump only]
  SESS --> SI[sysinfo pcitree]

  MAIN --> DRVIO[driver IOCTL optional PhoenixDrv]
```

Screenshots are single frames (GDI / DXGI / NVIDIA scanout), not live streaming. DumpFile reads only `%WinDir%\Minidump\*.dmp` with sanitized names.

## Building

Requirements: Node.js LTS + MySQL 8 for Latest; Visual Studio C++ x64 for `Phoenix-v3-Uhm/`.

```bash
cd Phoenix-v3-Uhm-Latest/backend && npm ci && npm run build
cd ../website && npm ci && npm run build
```

Agent/driver/updater: open `.vcxproj` under `Phoenix-v3-Uhm/`, Release | x64, align `PhoenixDrv/shared/config.hpp` hosts/ports with backend env.

## Known limits

None of this is "we will fix it later" hand-waving. These are structural problems you see once you trace a dashboard click to a PAC1 opcode.

- **Registry in memory:** one backend process owns live agents. Restart the node and live mappings are gone. No real horizontal scale.
- **Protocol soup:** PAC1 + PAC1 update + PHX wire + HTTP BFF. Same concepts implemented twice (PHX vs backend).
- **`AgentSession` monolith:** thousands of lines mixing framing, DB, webhooks, disk IO, and pending RPC. Easy to break, hard to test.
- **Split repo layout:** Latest without v3-Uhm binaries is incomplete; releases depend on artifact paths and manual alignment.
- **v1 / v2:** incompatible with Latest. Keep them only to see how not to do it.

```mermaid
flowchart TB
  ROOT[phoenix-ac Latest structural limits]
  ROOT --> A[Registry in memory on one node]
  ROOT --> B[PAC1 plus update plus PHX plus HTTP]
  ROOT --> C[AgentSession monolith]
  ROOT --> D[Client sources split across folders]
  ROOT --> E[v1 and v2 not compatible with Latest]
  ROOT --> F[Full rewrite still required]
```

## License

No `LICENSE` file in this monorepo.
