{ pkgs, self }:
let
  # The package's full Zig suite is checked independently. Re-running it in
  # every NixOS VM test obscures integration failures behind a second
  # 30-minute compile; this VM still builds the release binary it exercises.
  chock = pkgs.chock.overrideAttrs (_: {
    doCheck = false;
  });
  oidcTestCert = pkgs.writeText "chock-nixos-oidc-test.crt" ''
    -----BEGIN CERTIFICATE-----
    MIIBqzCCAVGgAwIBAgIUAR9EhlHRyDK4PauaW60yVPj36AcwCgYIKoZIzj0EAwIw
    IzEhMB8GA1UEAwwYQ2hvY2sgTml4T1MgT0lEQyBUZXN0IENBMB4XDTI2MTEwNzA4
    MDIxMFoXDTQ2MTEwMjA4MDIxMFowIzEhMB8GA1UEAwwYQ2hvY2sgTml4T1MgT0lE
    QyBUZXN0IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEz2Ussl1wvR1riqb/
    Uqji33gw1e6+qIVSI1jdru+SZs00IUaWBGKkr/2qf4T7novKcnzdaky3qc14+vPa
    iAlMg6NjMGEwHQYDVR0OBBYEFIYpaNKX6MaP9YkuplhZ5mQ5nJM+MB8GA1UdIwQY
    MBaAFIYpaNKX6MaP9YkuplhZ5mQ5nJM+MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0P
    AQH/BAQDAgEGMAoGCCqGSM49BAMCA0gAMEUCIFOPPr6NX/ddE+EjlCRp2Jm7LJvP
    zuWAHdCq7reVdfzIAiEAmdZ7kIifWrddapEB1kmLyFHjLoRCCgR2lCN93tf/X2g=
    -----END CERTIFICATE-----
  '';
  oidcServerCert = pkgs.writeText "chock-nixos-oidc-test-server.crt" ''
    -----BEGIN CERTIFICATE-----
    MIIBwTCCAWegAwIBAgIUPnRprg2AlAfz3YhraioD5gLDjYYwCgYIKoZIzj0EAwIw
    IzEhMB8GA1UEAwwYQ2hvY2sgTml4T1MgT0lEQyBUZXN0IENBMB4XDTI2MTEwNzA4
    MDIyMloXDTQ2MTEwMjA4MDIyMlowFDESMBAGA1UEAwwJMTI3LjAuMC4xMFkwEwYH
    KoZIzj0CAQYIKoZIzj0DAQcDQgAEHgTwp4/sSrbNlAzFUDu+WBgcvYMYdoX6EMl5
    BLTPIcweOV2PTykTtCq/lFDJK6Y+0xy/zNlrNY+RcvlQ6BvuiKOBhzCBhDAPBgNV
    HREECDAGhwR/AAABMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgWgMBMGA1Ud
    JQQMMAoGCCsGAQUFBwMBMB0GA1UdDgQWBBSGRyPnhvn7A01WWLzcWLLaZjEZDzAf
    BgNVHSMEGDAWgBSGKWjSl+jGj/WJLqZYWeZkOZyTPjAKBggqhkjOPQQDAgNIADBF
    AiEA1J/M2Vz9Rhzj4I+Dds6sYNBNlJh3axP9sg3gifmnJy8CIGzbdmmFdiNy6AWM
    ucAiiTQOs/eNsY8Q9IQmBxYXYzy6
    -----END CERTIFICATE-----
  '';
  oidcTestKey = pkgs.writeText "chock-nixos-oidc-test.key" ''
    -----BEGIN EC PRIVATE KEY-----
    MHcCAQEEIFCYZGZKS9Yscpfu2/N0x9/7vGkbV8+hkH+HEQ43jJg9oAoGCCqGSM49
    AwEHoUQDQgAEHgTwp4/sSrbNlAzFUDu+WBgcvYMYdoX6EMl5BLTPIcweOV2PTykT
    tCq/lFDJK6Y+0xy/zNlrNY+RcvlQ6BvuiA==
    -----END EC PRIVATE KEY-----
  '';
  oidcPython = pkgs.python3.withPackages (ps: [ ps.cryptography ]);
  oidcFixture = pkgs.writeText "chock-nixos-oidc-fixture.py" ''
    import base64
    import hashlib
    import json
    import secrets
    import ssl
    import sys
    import time
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import parse_qs, urlencode, urlparse

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    ISSUER = "https://127.0.0.1:8787"
    CLIENT_ID = "chock-nixos-test"
    CLIENT_SECRET = "nixos-test-secret"
    CALLBACK = "http://127.0.0.1:7374/auth/callback"
    KID = "chock-nixos-test-key"

    with open("${oidcTestKey}", "rb") as handle:
        KEY = serialization.load_pem_private_key(handle.read(), password=None)

    def b64(data):
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    def sign_jwt(claims):
        header = {"alg": "ES256", "kid": KID, "typ": "JWT"}
        signed = b64(json.dumps(header).encode()) + "." + b64(json.dumps(claims).encode())
        r, s = decode_dss_signature(KEY.sign(signed.encode(), ec.ECDSA(hashes.SHA256())))
        return signed + "." + b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))

    def jwks():
        numbers = KEY.public_key().public_numbers()
        return {"keys": [{
            "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": KID,
            "x": b64(numbers.x.to_bytes(32, "big")),
            "y": b64(numbers.y.to_bytes(32, "big")),
        }]}

    DISCOVERY = {
        "issuer": ISSUER,
        "authorization_endpoint": ISSUER + "/authorize",
        "token_endpoint": ISSUER + "/token",
        "jwks_uri": ISSUER + "/jwks",
        "code_challenge_methods_supported": ["S256"],
        "id_token_signing_alg_values_supported": ["ES256"],
    }

    # Authorization codes waiting for /token, and the fault for the next token.
    codes = {}
    next_fault = [None]

    class Handler(BaseHTTPRequestHandler):
        def reply(self, status, body=b"", content_type="application/json", headers=()):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for name, value in headers:
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def refuse(self, status, why):
            print("refused: " + why, file=sys.stderr, flush=True)
            self.reply(status, json.dumps({"error": "invalid_request", "error_description": why}).encode())

        def reply_json(self, value):
            self.reply(200, json.dumps(value).encode())

        def do_GET(self):
            url = urlparse(self.path)
            query = {k: v[0] for k, v in parse_qs(url.query).items()}
            if url.path == "/.well-known/openid-configuration":
                self.reply_json(DISCOVERY)
            elif url.path == "/jwks":
                self.reply_json(jwks())
            elif url.path == "/authorize":
                self.authorize(query)
            elif url.path == "/fixture/fault":
                next_fault[0] = query.get("mode")
                self.reply_json({"fault": next_fault[0]})
            else:
                self.send_error(404)

        def authorize(self, query):
            expected = {
                "response_type": "code",
                "client_id": CLIENT_ID,
                "redirect_uri": CALLBACK,
                "code_challenge_method": "S256",
            }
            for name, value in expected.items():
                if query.get(name) != value:
                    return self.refuse(400, "authorize " + name + "=" + repr(query.get(name)))
            if "openid" not in query.get("scope", "").split():
                return self.refuse(400, "authorize scope lacks openid")
            for name in ("state", "nonce", "code_challenge"):
                if not query.get(name):
                    return self.refuse(400, "authorize " + name + " is missing")
            code = secrets.token_urlsafe(24)
            codes[code] = query
            location = CALLBACK + "?" + urlencode({"code": code, "state": query["state"]})
            self.reply(302, headers=[("Location", location)])

        def do_POST(self):
            if urlparse(self.path).path != "/token":
                self.send_error(404)
                return
            length = int(self.headers.get("Content-Length", "0"))
            form = {k: v[0] for k, v in parse_qs(self.rfile.read(length).decode()).items()}
            basic = base64.b64encode((CLIENT_ID + ":" + CLIENT_SECRET).encode()).decode()
            if self.headers.get("Authorization") != "Basic " + basic:
                return self.refuse(401, "token client authentication failed")
            if form.get("grant_type") != "authorization_code":
                return self.refuse(400, "token grant_type=" + repr(form.get("grant_type")))
            request = codes.pop(form.get("code", ""), None)
            if request is None:
                return self.refuse(400, "token code is unknown or used")
            if form.get("redirect_uri") != request["redirect_uri"]:
                return self.refuse(400, "token redirect_uri differs from authorize")
            digest = hashlib.sha256(form.get("code_verifier", "").encode()).digest()
            if b64(digest) != request["code_challenge"]:
                return self.refuse(400, "token code_verifier does not match code_challenge")

            fault, next_fault[0] = next_fault[0], None
            now = int(time.time())
            claims = {
                "iss": ISSUER,
                "aud": CLIENT_ID,
                "sub": "nixos-test-admin",
                "name": "Nixos Test Admin",
                "email": "admin@chock.test",
                "nonce": request["nonce"],
                "iat": now,
                "exp": now + 300,
            }
            if fault == "nonce":
                claims.update(sub="nixos-test-wrong-nonce", nonce="not-the-nonce")
            elif fault == "aud":
                claims.update(sub="nixos-test-wrong-aud", aud="another-client")
            if fault:
                print("issued an ID token with fault " + fault, file=sys.stderr, flush=True)
            self.reply_json({
                "access_token": secrets.token_urlsafe(24),
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": "openid profile email",
                "id_token": sign_jwt(claims),
            })

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 8787), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("${oidcServerCert}", "${oidcTestKey}")
    server.socket = context.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
    server.serve_forever()
  '';
in
pkgs.testers.runNixOSTest {
  name = "chock-daemon-service";

  # A runner without KVM must still run this. qemu takes `accel=kvm:tcg`, so
  # it emulates where it cannot accelerate.
  requiredFeatures.kvm = false;

  nodes.machine =
    { pkgs, ... }:
    {
      imports = [ self.nixosModules.chock-daemon ];
      environment.systemPackages = [
        pkgs.iproute2
        pkgs.curl
        pkgs.postgresql
        pkgs.util-linux
      ];
      security.pki.certificateFiles = [ oidcTestCert ];
      environment.etc."chock-web-test.env".text = ''
        CHOCK_BOUNDARY_WEB=web-only
      '';
      systemd.services.chock-oidc-test-fixture = {
        description = "Local identity provider fixture for Chock's NixOS test";
        wantedBy = [ "multi-user.target" ];
        serviceConfig = {
          Type = "simple";
          ExecStart = "${oidcPython}/bin/python3 ${oidcFixture}";
          Restart = "on-failure";
          DynamicUser = true;
          PrivateTmp = true;
          ProtectSystem = "strict";
        };
      };
      services.postgresql = {
        enable = true;
        ensureDatabases = [ "chock" ];
        ensureUsers = [
          {
            name = "chock";
            ensureDBOwnership = true;
          }
        ];
      };
      environment.etc."chock-daemon-test.env".text = ''
        CHOCK_BOUNDARY_DAEMON=daemon-only
        CHOCK_DATABASE_URL=postgresql:///chock?host=/run/postgresql&user=chock&sslmode=disable
      '';
      services.chock-daemon.enable = true;
      services.chock-daemon.package = chock;
      services.chock-daemon.environmentFiles = [ "/etc/chock-daemon-test.env" ];
      services.chock-daemon.web.enable = true;
      services.chock-daemon.web.externalUrl = "http://127.0.0.1:7374";
      services.chock-daemon.web.environmentFiles = [ "/etc/chock-web-test.env" ];
      systemd.services.chock-daemon = {
        after = [
          "postgresql.service"
          "postgresql-setup.service"
          "chock-oidc-test-fixture.service"
        ];
        requires = [
          "postgresql.service"
          "postgresql-setup.service"
          "chock-oidc-test-fixture.service"
        ];
      };
    };

  testScript = ''
    import shlex

    def command(label, text):
        print(f"nixos-test: {label}", flush=True)
        return machine.succeed(text)

    def wait_for(label, text):
        print(f"nixos-test: waiting for {label}", flush=True)
        return machine.wait_until_succeeds(text)

    machine.start()
    wait_for("OIDC fixture unit", "systemctl is-active --quiet chock-oidc-test-fixture.service")
    wait_for("OIDC discovery document", "curl --fail --silent --cacert ${oidcTestCert} https://127.0.0.1:8787/.well-known/openid-configuration | grep -q authorization_endpoint")
    wait_for("daemon unit", "systemctl is-active --quiet chock-daemon.service")
    wait_for("web unit", "systemctl is-active --quiet chock-web.service")
    wait_for("daemon process", "test \"$(systemctl show -p MainPID --value chock-daemon.service)\" -gt 0")
    wait_for("web process", "test \"$(systemctl show -p MainPID --value chock-web.service)\" -gt 0")
    command("web has no restart", "test \"$(systemctl show -p NRestarts --value chock-web.service)\" = 0")
    daemon_pid = command("get daemon pid", "systemctl show -p MainPID --value chock-daemon.service").strip()
    web_pid = command("get web pid", "systemctl show -p MainPID --value chock-web.service").strip()
    command("daemon and gateway use separate UIDs", f"test \"$(stat -c %u /proc/{daemon_pid})\" != \"$(stat -c %u /proc/{web_pid})\"")
    command("gateway cannot read daemon OIDC configuration", "runuser -u chock-web -- test ! -r /var/lib/chock/service-oidc.json")
    command("daemon env isolation", f"grep -a -q 'CHOCK_BOUNDARY_DAEMON=daemon-only' /proc/{daemon_pid}/environ")
    command("daemon excludes web env", f"! grep -a -q 'CHOCK_BOUNDARY_WEB=web-only' /proc/{daemon_pid}/environ")
    command("web env isolation", f"grep -a -q 'CHOCK_BOUNDARY_WEB=web-only' /proc/{web_pid}/environ")
    command("web excludes daemon env", f"! grep -a -q 'CHOCK_BOUNDARY_DAEMON=daemon-only' /proc/{web_pid}/environ")
    command("daemon has no OIDC environment configuration", f"! tr '\\0' '\\n' < /proc/{daemon_pid}/environ | grep -q '^CHOCK_OIDC_'")
    command("web excludes OIDC provider configuration", f"! tr '\\0' '\\n' < /proc/{web_pid}/environ | grep -q '^CHOCK_OIDC_'")
    command("web excludes OIDC client secret", f"! grep -a -q 'CHOCK_OIDC_CLIENT_SECRET=' /proc/{web_pid}/environ")
    command("daemon CA bundle", f"ca_file=$(tr '\\0' '\\n' < /proc/{daemon_pid}/environ | sed -n 's/^SSL_CERT_FILE=//p'); test -n \"$ca_file\" && test -r \"$ca_file\"")
    command("web CA bundle", f"ca_file=$(tr '\\0' '\\n' < /proc/{web_pid}/environ | sed -n 's/^SSL_CERT_FILE=//p'); test -n \"$ca_file\" && test -r \"$ca_file\"")
    wait_for("daemon socket", "test -S /run/chock-daemon/daemon.sock")
    command("daemon control socket is group-only", "test \"$(stat -c %a /run/chock-daemon/daemon.sock)\" = 770")
    wait_for("web socket", "test -S /run/chock-web/serve.sock")
    command("PostgreSQL readiness", "pg_isready -h /run/postgresql")
    command("state directory mode", "test \"$(stat -c %a /var/lib/chock)\" = 700")
    command("web socket group mode", "test \"$(stat -c %a /run/chock-web/serve.sock)\" = 660")
    command("unrelated user cannot reach daemon control socket", "! runuser -u nobody -- curl --silent --unix-socket /run/chock-daemon/daemon.sock http://localhost/api/auth/status >/dev/null 2>&1")
    command("state directory owner", "test \"$(stat -c %U:%G /var/lib/chock)\" = chock:chock")
    command("daemon has no TCP listener", "! ss -lnt | grep -q ':7373 '")
    command("serve UI", "runuser -u chock-web -- curl --fail --silent --compressed --unix-socket /run/chock-web/serve.sock http://localhost/index.html | grep -qi '<!doctype html>'")
    command("first-run setup serves the Phantom app", "runuser -u chock-web -- curl --fail --silent --compressed --unix-socket /run/chock-web/serve.sock http://localhost/setup | grep -q 'boot.js'")
    command("first-run Phantom WASM is available", "runuser -u chock-web -- curl --fail --silent --compressed --output /dev/null --unix-socket /run/chock-web/serve.sock http://localhost/chock-web.wasm")
    command("daemon-owned OIDC setup", "runuser -u chock-web -- curl --silent --output /dev/null --write-out '%{http_code}' --unix-socket /run/chock-web/serve.sock -H 'Origin: http://127.0.0.1:7374' -H 'Content-Type: application/json' --data '{\"provider\":\"kanidm\",\"issuer\":\"https://127.0.0.1:8787\",\"discovery_url\":\"https://127.0.0.1:8787/.well-known/openid-configuration\",\"client_id\":\"chock-nixos-test\",\"client_secret\":\"nixos-test-secret\",\"admin_subject\":\"nixos-test-admin\"}' http://localhost/api/setup/oidc | grep -qx 201")
    command("OIDC configuration is private", "test \"$(stat -c %a /var/lib/chock/service-oidc.json)\" = 600 && grep -q 'nixos-test-secret' /var/lib/chock/service-oidc.json")
    command("OIDC setup cannot be repeated", "runuser -u chock-web -- curl --silent --output /dev/null --write-out '%{http_code}' --unix-socket /run/chock-web/serve.sock -H 'Origin: http://127.0.0.1:7374' -H 'Content-Type: application/json' --data '{}' http://localhost/api/setup/oidc | grep -qx 409")
    command("local setup is closed after OIDC setup", "runuser -u chock-web -- curl --silent --output /dev/null --write-out '%{http_code}' --unix-socket /run/chock-web/serve.sock -H 'Origin: http://127.0.0.1:7374' -H 'Content-Type: application/json' --data '{\"username\":\"another-admin\",\"password\":\"correct horse battery staple\"}' http://localhost/api/setup/local | grep -qx 403")
    command("gateway auth mode", "runuser -u chock-web -- curl --fail --silent --unix-socket /run/chock-web/serve.sock http://localhost/api/auth/status | grep -q '\"mode\":\"oidc\"'")
    gateway = "runuser -u chock-web -- curl --silent --unix-socket /run/chock-web/serve.sock"
    idp = "curl --silent --cacert ${oidcTestCert}"
    callback_base = "http://127.0.0.1:7374"
    pg = "runuser -u chock -- psql 'postgresql:///chock?host=/run/postgresql&user=chock&sslmode=disable' -Atqc"

    def headers_of(dump, name):
        values = []
        for line in dump.splitlines():
            key, _, value = line.partition(":")
            if key.strip().lower() == name:
                values.append(value.strip())
        return values

    def status_of(dump):
        return int(dump.splitlines()[0].split()[1])

    def cookie_value(dump, name):
        for value in headers_of(dump, "set-cookie"):
            if value.startswith(name + "="):
                return value.split(";")[0].split("=", 1)[1]
        return None

    # A grep over the header dump throws the answer away when it does not
    # match. Assert here instead, so a failure prints what the gateway sent.
    def expect_login_redirect(label):
        dump = command(label, f"{gateway} --dump-header - --output /dev/null http://localhost/auth/login")
        assert status_of(dump) == 302, dump
        assert headers_of(dump, "location")[0].startswith("https://127.0.0.1:8787/authorize?"), dump

    expect_login_redirect("OIDC login redirect")
    # Twice in a row. One request proves less: a second sign-in start, with
    # the first still pending, is its own case.
    expect_login_redirect("OIDC login redirect, repeated")

    def drive_login(label):
        # The gateway, then the provider, then the gateway callback, as a browser would.
        begin = command(f"{label}: gateway starts login", f"{gateway} --dump-header - --output /dev/null http://localhost/auth/login")
        assert status_of(begin) == 302, begin
        state = cookie_value(begin, "chock_oidc_state")
        assert state, begin
        authorize = headers_of(begin, "location")[0]
        assert authorize.startswith("https://127.0.0.1:8787/authorize?"), authorize
        granted = command(f"{label}: provider authorizes", f"{idp} --dump-header - --output /dev/null {shlex.quote(authorize)}")
        assert status_of(granted) == 302, granted
        callback = headers_of(granted, "location")[0]
        assert callback.startswith(callback_base + "/auth/callback?code="), callback
        target = "http://localhost" + callback[len(callback_base):]
        return machine.succeed(f"{gateway} --dump-header - --output /dev/null --cookie chock_oidc_state={state} {shlex.quote(target)}")

    def session_count():
        return int(command("count login sessions", f"{pg} 'SELECT COUNT(*) FROM auth_sessions'").strip())

    def identity_count(subject):
        return int(command("count identities", f"{pg} \"SELECT COUNT(*) FROM identities WHERE subject = '{subject}'\"").strip())

    command("people directory needs a session", f"{gateway} --output /dev/null --write-out '%{{http_code}}' http://localhost/api/people | grep -qx 401")
    sessions_before = session_count()
    finished = drive_login("login")
    assert status_of(finished) == 302, finished
    assert headers_of(finished, "location") == ["/"], finished
    session = cookie_value(finished, "chock_session")
    assert session, finished
    assert session_count() == sessions_before + 1
    assert identity_count("nixos-test-admin") == 1
    for fault, subject in (("nonce", "nixos-test-wrong-nonce"), ("aud", "nixos-test-wrong-aud")):
        command(f"{fault} fault armed", f"{idp} --fail 'https://127.0.0.1:8787/fixture/fault?mode={fault}' | grep -q {fault}")
        refused = drive_login(f"{fault} fault")
        assert status_of(refused) == 502, refused
        assert cookie_value(refused, "chock_session") is None, refused
        command(f"{fault} fault reached the daemon", f"journalctl -u chock-oidc-test-fixture.service | grep -q 'issued an ID token with fault {fault}'")
        assert identity_count(subject) == 0
        assert session_count() == sessions_before + 1

    command("administrator subject became instance admin", f"{pg} \"SELECT instance_role FROM identities WHERE subject = 'nixos-test-admin'\" | grep -qx instance_admin")
    command("session reaches an authenticated route", f"{gateway} --fail --output /dev/null --cookie chock_session={session} http://localhost/api/projects")
    people = command("people directory with the session", f"{gateway} --write-out '\\nstatus=%{{http_code}}' --cookie chock_session={session} http://localhost/api/people")
    assert people.endswith("status=200"), people
    assert "Nixos Test Admin" in people, people

    command("cross-origin setup rejected", "runuser -u chock-web -- curl --silent --output /dev/null --write-out '%{http_code}' --unix-socket /run/chock-web/serve.sock -H 'Origin: https://attacker.example' -X POST http://localhost/api/setup/local | grep -qx 403")
    command("PostgreSQL query", "runuser -u chock -- psql 'postgresql:///chock?host=/run/postgresql&user=chock&sslmode=disable' -Atqc 'SELECT 1' | grep -qx 1")
    command("schema persistence", "runuser -u chock -- psql 'postgresql:///chock?host=/run/postgresql&user=chock&sslmode=disable' -Atqc 'SELECT COUNT(*) FROM chock_schema' | grep -qx 5")
    command("unauthenticated export rejection", "runuser -u chock-web -- curl --silent --output /dev/null --write-out '%{http_code}' --unix-socket /run/chock-web/serve.sock http://localhost/api/export/instance | grep -qx 401")
    command("write persistence sentinel", "runuser -u chock -- psql 'postgresql:///chock?host=/run/postgresql&user=chock&sslmode=disable' -c \"CREATE TABLE IF NOT EXISTS nixos_test_sentinel (id INTEGER PRIMARY KEY, value TEXT NOT NULL); INSERT INTO nixos_test_sentinel(id, value) VALUES (1, 'persisted') ON CONFLICT (id) DO NOTHING;\"")

    command("restart daemon", "systemctl restart chock-daemon.service")
    wait_for("daemon socket after restart", "test -S /run/chock-daemon/daemon.sock")
    command("daemon active after restart", "systemctl is-active --quiet chock-daemon.service")
    wait_for("web active after restart", "systemctl is-active --quiet chock-web.service")
    command("OIDC configuration survives daemon restart", "runuser -u chock-web -- curl --fail --silent --unix-socket /run/chock-web/serve.sock http://localhost/api/auth/status | grep -q '\"mode\":\"oidc\"'")
    expect_login_redirect("OIDC login survives daemon restart")
    command("sentinel survives restart", "runuser -u chock -- psql 'postgresql:///chock?host=/run/postgresql&user=chock&sslmode=disable' -Atqc 'SELECT value FROM nixos_test_sentinel WHERE id = 1' | grep -qx persisted")
    command("schema survives restart", "runuser -u chock -- psql 'postgresql:///chock?host=/run/postgresql&user=chock&sslmode=disable' -Atqc 'SELECT COUNT(*) FROM chock_schema' | grep -qx 5")
  '';
}
