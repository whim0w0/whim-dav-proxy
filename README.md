# whim-dav-proxy

A WebDAV proxy that supports encryption and decryption of both file names and file contents.


## Command Line

```
Usage: whim-dav-proxy [OPTIONS]

Options:
  -c, --config <CONFIG>  Path to the configuration file [default: config.yaml]
  -h, --help             Print help
  -V, --version          Print version
```

The program reads a YAML configuration file and starts one listening server per
configured backend. If the config file is missing or invalid, the program exits
with a non-zero status code and prints the reason to stderr.


## Usage

1. Write a `config.yaml` file and place it in the same directory as the binary (see the example below).
2. Start the program:

   ```sh
   ./whim-dav-proxy                 # uses ./config.yaml
   ./whim-dav-proxy -c myconf.yaml  # uses a custom config file
   ```

3. Connect your WebDAV client to the listening address.

Below is an example configuration:

```yaml
# whim-dav-proxy configuration file
log:
  level: info
  format: console

backends:
  # backend name, supports multiple
  - name: "expmple-web-dav"
    listen:
      # listen port
      port: 411
    webdav_host:
      # upstream WebDAV server address
      url: "http://example.com" # address
      # optional credentials
      username: "user"
      password: "pass"
    encryption:
      # enable encryption
      enable: true
      # encryption password
      password: "123456"
      # optional algorithms: aesctr / chacha20 (stream ciphers)
      #                      aesgcm / chacha20poly1305 / aesgcmsiv (block AEAD, supports random-access Range)
      enc_type: "aesctr"
      # enable filename encryption
      enc_name: false
      # filename encryption suffix
      enc_suffix: ".enc"
```


## Configuration Reference

### `log` (optional)

| Field    | Type   | Default | Description                                                        |
|----------|--------|---------|--------------------------------------------------------------------|
| `level`  | string | `info`  | Log level: `error`, `warn`, `info`, `debug`, `trace`.              |
| `format` | string | `json`  | Log format. `console` / `text` / `pretty` = human-readable, anything else = `json`. |

### `backends` (required, array of one or more entries)

Each entry starts a listener that proxies to one upstream WebDAV server. You can
declare multiple backends (each on its own port) in a single config file.

#### `name`

Required. Arbitrary label for the backend (used in logs). Must be unique per file.

#### `listen`

| Field  | Type   | Default | Description                                                          |
|--------|--------|---------|----------------------------------------------------------------------|
| `port` | u16    | —       | Port to listen on (`0.0.0.0:<port>`). Required; must be 1–65535 and not conflict with another backend. |

#### `webdav_host`

| Field                 | Type    | Default | Description                                                                   |
|-----------------------|---------|---------|-------------------------------------------------------------------------------|
| `url`                 | string  | —       | Upstream WebDAV server URL. Required. May include a path prefix, e.g. `https://host/webdav`. |
| `username` / `password` | string | —       | Optional credentials. When set, a `Basic` `Authorization` header is injected into every forwarded request. |
| `insecure_skip_verify` | bool   | `false` | Skip TLS certificate verification for the upstream (e.g. self-signed certs). Not recommended. |

#### `encryption`

Optional block. Omit it (or set `enable: false`) to run as a plain proxy.

| Field       | Type    | Default    | Description                                                                                   |
|-------------|---------|------------|-----------------------------------------------------------------------------------------------|
| `enable`    | bool    | —          | Master switch for encryption.                                                                 |
| `password`  | string  | `""`       | Secret used to derive encryption keys. Required when `enable: true`. Losing it makes data undecryptable. |
| `enc_type`  | string  | `aesctr`   | Cipher algorithm (see below).                                                                 |
| `enc_name`  | bool    | `false`    | Also encrypt file names on the upstream (not just file contents).                             |
| `enc_suffix`| string  | *(see note)* | Suffix appended to encrypted file names, e.g. `.enc`. When unset, the original file extension is kept. Leading dot is optional. |

Supported `enc_type` values:

| Value              | Kind      | Notes                                            |
|--------------------|-----------|--------------------------------------------------|
| `aesctr`           | stream    | AES-256-CTR                                      |
| `chacha20`         | stream    | ChaCha20                                         |
| `aesgcm`           | blocked AEAD | supports random-access `Range` requests       |
| `chacha20poly1305` | blocked AEAD | (alias `chacha20-poly1305`)                   |
| `aesgcmsiv`        | blocked AEAD | (alias `aes-gcm-siv`)                         |

Stream ciphers encrypt/decrypt a continuous byte stream; blocked AEAD ciphers
process fixed-size blocks and therefore support random-access HTTP `Range`
requests on large files.


## Inspiration

This project is inspired by [alist-encrypt](https://github.com/traceless/alist-encrypt),
which applies client-side encryption/decryption on top of a WebDAV-compatible
backend. Many design decisions — such as keeping directory names in plaintext
while encrypting file names and file contents — follow its approach.


## License

Released under the [MIT License](./LICENSE).
Copyright (c) 2026 whim0w0