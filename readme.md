### lurker


lurker is a selfhostable, privacy-focused reddit client with SSO support,
user preferences, and PWA capabilities. it is better than old-reddit because:

- it renders well on mobile with responsive layouts
- it respects `prefers-color-scheme` with multiple theme options
- no account necessary to subscribe to subreddits
- no account necessary for over-18 content
- installable as a Progressive Web App (PWA)
- customizable per-user experience (infinite scroll, layout, themes)

i host a version for myself and a few friends. reach out to
me if you would like an invite.

### features

- **authentication & security**
  - SSO via Remote Header Authorization (Authelia, Authentik, etc.)
  - invite-only user management
  - admin dashboard with invite tokens
  - rate limiting and reverse proxy support

- **user experience**
  - minimal use of client-side javascript
  - account-based subscription system
  - per-user preferences (infinite scroll, theme, layout)
  - "Never Ending Reddit" infinite scroll option
  - Classic RES-style compact layout for desktop
  - multiple themes: auto (system), light, dark, RES night mode
  - Progressive Web App (PWA) - installable on mobile devices

- **content & navigation**
  - pagination with infinite scroll option
  - comment collapsing, jump-to-next/prev comment
  - crosspost support
  - "search on undelete" url for deleted comments
  - over-18, spoiler images are hidden by default
  - inline post thumbnail expansion

i use lurker daily, and above features are pretty good for
my use.

### gallery

| ![login](./img/login.png) | ![search](./img/search.png)      | ![subreddit](./img/subreddit.png) |
| ------------------------- | -------------------------------- | --------------------------------- |
| login                     | search                           | subreddit view                    |

| ![subs](./img/subs.png)   | ![gallery](./img/gallery.png)    | ![comments](./img/comments.png)   |
| ------------------------- | -------------------------------- | --------------------------------- |
| subscriptions page        | inline post thumbnail expand     | comments view                     |

| ![collapse](./img/collapse.png) | ![invite](./img/invite.png)      | ![light](./img/light.png)  | ![mobile](./img/mobile.png) |
| ------------------------------- | -------------------------------- | -------------------------- | --------------------------- |
| collapse comments               | admin dashboard & invites table  | light mode                 | mobile optimized page       |

### setup

you can run lurker as a systemd service on nixos:

```nix
inputs.lurker.url= "git+https://github.com/voc0der/lurker";
  .
  .
  .
services.lurker = {
  enable = true;
  port = 9495;
};
```

or with the docker image:

```bash
# pull the latest image from gh container registry
$ docker pull ghcr.io/voc0der/lurker:latest

REPOSITORY                   TAG       IMAGE ID       CREATED        SIZE
ghcr.io/voc0der/lurker   latest    ba3733164889   ???            227MB

# start lurker in a container
#
# lurker stores data in /data,
# so create a volume on the host accordingly:
$ docker run -v /your/host/lurker-data:/data -p 3000 ghcr.io/voc0der/lurker:latest
```

or with docker compose:

```yaml
---
services:
  lurker:
    image: ghcr.io/voc0der/lurker:latest
    container_name: lurker
    environment:
      - PUID=1000              # user ID for file permissions
      - PGID=1000              # group ID for file permissions
      - LURKER_PORT=3000
      - LOG_LEVEL=info         # debug, info, warn, or error
      # - REMOTE_HEADER_LOGIN=true  # uncomment for SSO
      # - ADMIN_GROUP=admin         # SSO admin group name
    volumes:
      - /your/host/lurker-data:/data
    ports:
      - "3000:3000"
    restart: unless-stopped
```

See `docker-compose.yaml` for a full compose example with **all** environment variables (and their defaults).


or with just [bun](https://bun.sh/):

```bash
bun run src/index.js
```

### usage

the instance is open to registrations when first started.
you can head to /register and create an account. this
account will be an admin account. you can click on your
username at the top-right to view the dashboard and to
invite other users to your instance. copy the link and send
it to your friends!

**user preferences**

each user can customize their experience via the dashboard:
- **Never Ending Reddit**: enable infinite scroll instead of pagination
- **Classic RES-style Layout**: toggle compact desktop layout (thumbnails on left)
- **Theme Preference**: choose between auto (system), light, dark, or RES night mode

**PWA installation**

lurker can be installed as a Progressive Web App on mobile devices:
- **Android**: Open in Chrome → Menu (⋮) → "Install app" or "Add to Home screen"
- **iOS**: Open in Safari → Share (⬆) → "Add to Home Screen"

once installed, lurker runs in standalone mode without browser chrome.

### environment variables

**server configuration**
- `LURKER_PORT`: port to listen on, defaults to `3000`
- `HTTP_BINDING`: IP address to bind to, defaults to `0.0.0.0`
- `LURKER_SSL_CERT_PATH`: path to SSL certificate file for HTTPS
- `LURKER_SSL_KEY_PATH`: path to SSL key file for HTTPS

**docker-specific**
- `PUID`: user ID for file permissions in Docker container, defaults to `1000`
- `PGID`: group ID for file permissions in Docker container, defaults to `1000`

**authentication & security**
- `JWT_SECRET_KEY`: secret key for JWT token signing (auto-generated if not set)
- `REMOTE_HEADER_LOGIN`: enable SSO via remote headers (`true`/`false`)
- `ADMIN_GROUP`: remote header group name that grants admin privileges, defaults to `admin`
- `REVERSE_PROXY_WHITELIST`: comma-separated list of trusted proxy IPs for `trust proxy` setting

**OIDC (OpenID Connect + PKCE)**
- `OIDC_ENABLED`: set to `true` to enable OIDC
- `OIDC_ISSUER_URL`: provider discovery URL (required)
- `OIDC_CLIENT_ID`: client ID (required)
- `OIDC_CLIENT_SECRET`: client secret (required)
- `OIDC_REDIRECT_URI`: callback URL (required, e.g. `https://lurker.example.com/auth/oidc/callback`)
- `OIDC_SCOPE`: scopes to request (default: `openid profile email`; add `offline_access` if your IdP requires it for refresh tokens)
- `OIDC_AUTO_REGISTER`: auto-create users on first OIDC login (default: `true`)
- `OIDC_ADMIN_CLAIM`: claim to use for admin mapping (default: `groups`)
- `OIDC_ADMIN_VALUE`: value in the admin claim that grants admin (default: `admin`)
- `OIDC_GROUP_CLAIM`: claim to read groups from and persist to the user record (default: `groups`)
- `OIDC_ALLOWED_GROUPS`: comma-separated list of groups required to log in / auto-register (optional)


**application settings**
- `LURKER_THEME`: name of CSS theme file. The file must be present in `src/public`
- `LOG_LEVEL`: logging verbosity - `debug`, `info` (default), `warn`, or `error`
- `RATE_LIMIT`: maximum requests per 15-minute window per IP, defaults to `100`

### technical

lurker uses an sqlite db to store accounts, invites and
subscriptions. it creates `lurker.db` in the current
directory. there is no way to configure this right now.

to hack on lurker:

```bash
nix shell .#        # get a devshell
nix build .#lurker  # build the thing
```

### todo

**completed features**
- [x] highlights for op, sticky etc.
- [x] open in reddit link
- [x] service worker for offline PWA support
- [x] subscription manager: bulk add, search/filter, unsubscribe all
- [x] support crossposts
- [x] PWA support (manifest, icons, meta tags)
- [x] user preferences system (infinite scroll, themes, layout)
- [x] "Never Ending Reddit" infinite scroll
- [x] Classic RES-style layout
- [x] multiple theme support (auto/light/dark/RES)
- [x] SSO via remote header authorization
- [x] collapse even singular comments
- [x] details tag on safari
- [x] expand/collapse comments
- [x] fix gallery thumbnails
- [x] fix spacing between comments
- [x] fix title rendering in views/comments.pug
- [x] pass query params into templates, add into pagination
- [x] placeholder for unresolvable thumbnails
- [x] set home to sum of subs
- [x] styles for info-containers
- [x] support 'more comments'

This is a fork of https://github.com/oppiliappan/lurker/ and I respect their work!
