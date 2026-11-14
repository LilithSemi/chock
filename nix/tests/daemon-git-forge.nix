{ pkgs, self }:
let
  chock = pkgs.chock.overrideAttrs (_: {
    doCheck = false;
  });

  forgeHost = "git.chock.test";
  # Resolves to the forge and is allowed, but the forge certificate does not name it.
  mismatchHost = "wrong-name.chock.test";
  # Resolves to the forge but is not on the allowlist.
  strangerHost = "other.chock.test";
  branch = "stable";

  certificates =
    pkgs.runCommand "chock-git-forge-certificates"
      {
        nativeBuildInputs = [ pkgs.openssl ];
      }
      ''
        mkdir $out
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
          -keyout ca.key -out $out/ca.crt -days 3650 -subj "/CN=Chock Git Forge Test CA" \
          -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign
        openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
          -keyout $out/server.key -out server.csr -subj "/CN=${forgeHost}"
        printf 'subjectAltName=DNS:${forgeHost}\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' > server.ext
        openssl x509 -req -in server.csr -CA $out/ca.crt -CAkey ca.key -CAcreateserial \
          -days 3650 -extfile server.ext -out $out/server.crt
      '';

  # Many commits that edit one file, then a full repack, so the pack the
  # forge serves holds deltas.
  forgeFixture = pkgs.writeShellScript "chock-git-forge-fixture" ''
    set -eu
    export PATH=${pkgs.git}/bin:${pkgs.coreutils}/bin:${pkgs.gnused}/bin:${pkgs.gawk}/bin
    export GIT_AUTHOR_NAME=Forge GIT_AUTHOR_EMAIL=forge@chock.test
    export GIT_COMMITTER_NAME=Forge GIT_COMMITTER_EMAIL=forge@chock.test
    bare=/var/lib/forge/team/project.git
    work=$(mktemp -d)
    git init --quiet --bare --initial-branch=${branch} "$bare"
    git init --quiet --initial-branch=${branch} "$work"
    cd "$work"
    # One awk, not 3000 processes. The file only has to be long and have
    # distinct lines, and a runner that emulates pays for every process.
    seq 1 3000 | awk '{ printf "line %d %064x\n", $1, $1 * 2654435761 }' > data.txt
    mkdir src
    printf '#!/bin/sh\necho forge\n' > src/run.sh
    chmod +x src/run.sh
    git add .
    git commit --quiet -m "first"
    for n in $(seq 1 25); do
      sed -i "$((n * 100))s/.*/edited in commit $n/" data.txt
      git commit --quiet -am "edit $n"
    done
    git checkout --quiet -b feature/extra
    echo extra > src/extra.txt
    git add src/extra.txt
    git commit --quiet -m "extra"
    git checkout --quiet ${branch}
    git push --quiet "$bare" ${branch} feature/extra
    git -C "$bare" repack --quiet -a -d -f --depth=50 --window=50
    git -C "$bare" prune-packed
  '';
in
pkgs.testers.runNixOSTest {
  name = "chock-daemon-git-forge";

  # A runner without KVM must still run this. qemu takes `accel=kvm:tcg`, so
  # it emulates where it cannot accelerate.
  requiredFeatures.kvm = false;

  nodes.machine =
    { config, pkgs, ... }:
    {
      imports = [ self.nixosModules.chock-daemon ];
      environment.systemPackages = [
        pkgs.curl
        pkgs.git
        pkgs.sqlite
      ];
      security.pki.certificateFiles = [ "${certificates}/ca.crt" ];
      networking.hosts."127.0.0.1" = [
        forgeHost
        mismatchHost
        strangerHost
      ];

      users.users.git = {
        isSystemUser = true;
        group = "git";
        home = "/var/lib/forge";
        createHome = true;
      };
      users.groups.git = { };
      services.fcgiwrap.instances.git = {
        process.user = "git";
        process.group = "git";
        socket.user = config.services.nginx.user;
        socket.group = config.services.nginx.group;
      };
      services.nginx = {
        enable = true;
        virtualHosts.${forgeHost} = {
          onlySSL = true;
          sslCertificate = "${certificates}/server.crt";
          sslCertificateKey = "${certificates}/server.key";
          locations."/".extraConfig = ''
            include ${pkgs.nginx}/conf/fastcgi_params;
            fastcgi_param SCRIPT_FILENAME ${pkgs.git}/libexec/git-core/git-http-backend;
            fastcgi_param GIT_PROJECT_ROOT /var/lib/forge;
            fastcgi_param GIT_HTTP_EXPORT_ALL "";
            fastcgi_param PATH_INFO $uri;
            fastcgi_pass unix:${config.services.fcgiwrap.instances.git.socket.address};
          '';
        };
      };

      services.chock-daemon.enable = true;
      services.chock-daemon.package = chock;
      services.chock-daemon.gitAllowedHosts = [
        forgeHost
        mismatchHost
      ];
      services.chock-daemon.web.enable = true;
      services.chock-daemon.web.externalUrl = "http://127.0.0.1:7374";
    };

  testScript = ''
    import datetime as dt
    import json
    import re
    import shlex

    def command(label, text):
        print(f"nixos-test: {label}", flush=True)
        # Generous, because a runner without KVM emulates and every step here
        # then takes about ten times as long.
        return machine.succeed(text, timeout=dt.timedelta(seconds=900))

    def wait_for(label, text):
        print(f"nixos-test: waiting for {label}", flush=True)
        return machine.wait_until_succeeds(text, timeout=dt.timedelta(seconds=300))

    forge_git = "runuser -u git -- env HOME=/var/lib/forge git -C /var/lib/forge/team/project.git"
    curl = "runuser -u chock -- curl"
    socket = "--unix-socket /run/chock-web/serve.sock"
    origin = "-H 'Origin: http://127.0.0.1:7374'"
    cookies = "--cookie /tmp/chock-admin.cookies --cookie-jar /tmp/chock-admin.cookies"

    def create_project(label, name, url):
        body = shlex.quote(json.dumps({"name": name, "repository_url": url}))
        out = f"/tmp/{label}.json"
        status = command(
            label,
            f"{curl} --silent --output {out} --write-out '%{{http_code}}' {cookies} {socket} {origin} "
            f"-H 'Content-Type: application/json' --data {body} http://localhost/api/projects",
        ).strip()
        return int(status), machine.succeed(f"cat {out}")

    def project_store():
        return machine.succeed("ls -A /var/lib/chock/projects | sort").split()

    machine.start()
    wait_for("forge TLS terminator", "systemctl is-active --quiet nginx.service")
    wait_for("forge CGI socket", "test -S /run/fcgiwrap-git.sock")
    wait_for("daemon", "systemctl is-active --quiet chock-daemon.service")
    wait_for("gateway socket", "test -S /run/chock-web/serve.sock")

    command("build the forge repository", "runuser -u git -- ${forgeFixture}")
    tip = command("forge branch tip", f"{forge_git} rev-parse refs/heads/${branch}").strip()
    total = int(command("forge commit count", f"{forge_git} rev-list --count refs/heads/${branch}").strip())
    assert total == 26, total

    # The glob is expanded by the calling shell, so it has to run with the repository as
    # its working directory. `git -C` moves git and not the shell.
    pack = command(
        "forge pack listing",
        f"cd /var/lib/forge/team/project.git && {forge_git} verify-pack -v objects/pack/*.idx",
    )
    deltas = [line for line in pack.splitlines() if re.fullmatch(r"[0-9a-f]{40} \w+ +\d+ \d+ \d+ \d+ [0-9a-f]{40}", line)]
    assert len(deltas) >= 20, f"forge pack holds {len(deltas)} deltas:\n{pack}"
    loose = command("forge loose objects", f"{forge_git} count-objects -v")
    assert re.search(r"^count: 0$", loose, re.M), loose
    command("forge advertises protocol v2", "curl --fail --silent --cacert ${certificates}/ca.crt -H 'Git-Protocol: version=2' 'https://${forgeHost}/team/project.git/info/refs?service=git-upload-pack' | grep -aq 'version 2'")

    daemon_pid = command("daemon pid", "systemctl show -p MainPID --value chock-daemon.service").strip()
    command(
        "daemon SSL_CERT_FILE bundle holds the forge CA",
        f"ca_file=$(tr '\\0' '\\n' < /proc/{daemon_pid}/environ | sed -n 's/^SSL_CERT_FILE=//p'); "
        "ca_line=$(sed -n 2p ${certificates}/ca.crt); grep -qF \"$ca_line\" \"$ca_file\"",
    )
    command(
        "daemon allowlist names the forge",
        f"tr '\\0' '\\n' < /proc/{daemon_pid}/environ | grep -qx 'CHOCK_GIT_ALLOWED_HOSTS=${forgeHost},${mismatchHost}'",
    )

    command(
        "create first administrator",
        f"{curl} --silent --fail --output /dev/null -c /tmp/chock-admin.cookies {socket} {origin} -H 'Content-Type: application/json' -H 'X-Chock-Phantom-Auth: true' --data '{{\"username\":\"forge-admin\",\"password\":\"correct horse battery staple\"}}' http://localhost/api/setup/local",
    )

    before = project_store()
    assert before == [], before

    status, body = create_project("refused-host", "Stranger", "https://${strangerHost}/team/project.git")
    assert status == 403 and "repository host is not allowed" in body, (status, body)
    assert project_store() == before, project_store()

    status, body = create_project("refused-name", "Mismatch", "https://${mismatchHost}/team/project.git")
    assert status == 502, (status, body)
    assert project_store() == before, project_store()

    status, body = create_project("refused-repo", "Missing", "https://${forgeHost}/team/absent.git")
    assert status == 502, (status, body)
    assert project_store() == before, project_store()

    status, body = create_project("cloned", "Forge project", "https://${forgeHost}/team/project.git")
    if status != 200:
        # The status says a clone failed and not which leg of it did, so the daemon's own
        # words are the only account of that.
        print(machine.execute("journalctl -u chock-daemon.service --no-pager | tail -n 80")[1], flush=True)
    assert status == 200, (status, body)
    root = json.loads(body)["root"]
    assert root.startswith("/var/lib/chock/projects/"), root
    assert len(project_store()) == 1, project_store()

    chock_git = f"runuser -u chock -- env HOME=/var/lib/chock git -C {root}"
    assert command("clone status", f"{chock_git} status --porcelain").strip() == ""
    assert command("clone fsck", f"{chock_git} fsck --full 2>&1").strip() == ""
    assert command("clone branch", f"{chock_git} rev-parse --abbrev-ref HEAD").strip() == "${branch}"
    assert command("clone upstream", f"{chock_git} rev-parse --abbrev-ref @{{upstream}}").strip() == "origin/${branch}"
    assert command("clone tip", f"{chock_git} log -1 --format=%H").strip() == tip
    assert int(command("clone history", f"{chock_git} rev-list --count HEAD").strip()) == total
    command("clone file matches the forge", f"test \"$({chock_git} rev-parse HEAD:data.txt)\" = \"$({forge_git} rev-parse refs/heads/${branch}:data.txt)\"")
    command("clone keeps the executable bit", f"test -x {root}/src/run.sh")
    command("clone fetched every branch", f"test \"$({chock_git} for-each-ref --format='%(refname:short)' refs/remotes/origin | sort | tr '\\n' ' ')\" = 'origin/feature/extra origin/${branch} '")
    command("project is registered", "sqlite3 /var/lib/chock/daemon.sqlite \"SELECT source_kind FROM daemon_projects WHERE name = 'Forge project'\" | grep -qx git")
  '';
}
