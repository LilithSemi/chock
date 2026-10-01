# The kernel and the initrd a microVM guest boots, as two derivations.
#
# Shaped after DeterminateSystems/cloud-hypervisor-guest's own `bootinfo.nix`:
# a 6.1 LTS kernel, an uncompressed initrd from `makeInitrdNG`, and a static
# busybox for the init to be written in.
#
# **The guest binary is in the initrd**, and it is Chock's own one binary built
# for the guest's Linux target. Not a share and not a store path: a guest must be
# able to sandbox a tool call before anything is offered to it, and on a Mac there
# is no Linux `chock` in the host's store to share.
{
  lib,
  hostPkgs,
  guestPkgs,
}:
let
  busybox = guestPkgs.pkgsStatic.busybox;

  # 6.1 LTS, the same choice and the same reason as the example this follows:
  # a long term kernel avoids the issues a current one brings, and nothing here
  # needs a recent feature.
  kernel = guestPkgs.linuxKernel.kernels.linux_6_1;

  # **Only the modules the guest needs, and not the whole tree.** A guest booted
  # with every module of a kernel is a 146MB initramfs, and one that size does not
  # unpack: the guest came up, `/lib/modules` was there, and every file under it
  # was missing. The same root with six modules in it, 2.4MB, mounted its share
  # and got its vsock device. Measured on aarch64 on 2026-09-27.
  #
  # `makeModulesClosure` is what NixOS builds its own stage 1 with, so the
  # dependencies of each name below come in without being listed.
  modules = guestPkgs.makeModulesClosure {
    # **`kernel.modules` and not `kernel`.** A nixpkgs kernel's main output holds
    # `Image`, `dtbs` and `System.map` and no `lib/modules` at all, and this builder
    # answers "no modules were provided" rather than saying which path it looked in.
    kernel = kernel.modules;
    firmware = guestPkgs.emptyDirectory;
    rootModules = [
      # The channel to whoever started the guest. Three modules, and the order
      # they load in is the closure's to work out.
      "vsock"
      "vmw_vsock_virtio_transport"
      # The one mount every share arrives in, and the one a bind of a file is made
      # with: `read_file` puts a program's input over a directory it may not
      # change, and a guest without this answers `OverlayNotSupported`.
      "virtiofs"
      "overlay"
      # The transports a guest reaches its devices over. Built in on some
      # kernels, which is why the init does not fail when one is absent.
      "virtio_pci"
      "virtio_mmio"
      # What a tool call with a network needs. The driver builds the call its own
      # filtered network out of these, and a guest without them answers
      # `NetRouterUnavailable`: see `network_modules` and `filter_modules` in
      # `lib/chock-sandbox/linux/driver.zig`, which is where this list comes from.
      "dummy"
      "nf_tables"
      "nf_nat"
      "nft_chain_nat"
      "nft_redir"
      "nft_reject"
      "nf_conntrack"
      # The expressions those rules are made of. **A guest cannot autoload one.**
      # The kernel loads an expression on demand by running `/proc/sys/kernel/modprobe`,
      # and a rule naming one that is absent answers `ENOENT`, which reads as a
      # module missing and says nothing about which.
      "nft_ct"
      "nft_nat"
      "nft_reject_inet"
      "nf_reject_ipv4"
      "nf_reject_ipv6"
    ];
  };

  # Chock's own binary, for the guest. `chock guest` is a subcommand of it: see
  # `src/guest.zig`, and `test/plugin/one_binary.zig` for why there is no second
  # program to build here.
  chock = guestPkgs.chock;

  # Where the one virtiofs mount goes, and the tag Mirage exports it under. Each
  # directory the host offers appears as a name inside it.
  shares = "/mnt/shares";
  tag = "mirage";

  # **Two stages, because a sandbox cannot pivot out of an initramfs.**
  # `pivot_root` refuses to move a root mount that has no parent, and the
  # initramfs rootfs is exactly that, so every tool call in a guest rooted there
  # answered `PivotFailed`. Stage one makes a tmpfs, copies the image into it and
  # switches to it. Stage two is the guest proper, on a root it can pivot out of.
  stage_two = hostPkgs.writeScript "chock-guest-stage-2" ''
    #!/bin/busybox sh
    set -eu

    busybox mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
    exec >/dev/console 2>&1
    set -x

    ending() {
      busybox poweroff -f
    }
    trap ending EXIT

    busybox mount -t proc none /proc

    # **Where the kernel looks when it wants a module of its own accord.** It runs
    # `/sbin/modprobe`, which is not in this image, so an nftables expression a
    # rule names would never load and the rule would answer `ENOENT`.
    echo /bin/modprobe > /proc/sys/kernel/modprobe || true
    busybox mount -t sysfs none /sys

    # **Made after the devtmpfs, never before it.** Mounting devtmpfs on `/dev`
    # replaces what is in there, so a `shm` made in the root this switched from is
    # not there any more and the mount below answers `No such file or directory`.
    busybox mkdir -p /dev/shm
    busybox mount -t tmpfs tmpfs /dev/shm -o rw,nosuid,nodev
    busybox mount -t tmpfs tmpfs /tmp

    # The channel to whoever started this guest, and the one mount every share
    # arrives in. Nothing else is loaded: a module a guest does not need is a
    # driver a guest does not have.
    #
    # A name that is built into the kernel rather than a module is not an error:
    # `virtio_mmio` is built in on some, and the mount below works anyway.
    for one in vsock vmw_vsock_virtio_transport virtio_pci virtio_mmio virtiofs overlay \
      dummy nf_tables nf_nat nft_chain_nat nft_redir nft_reject nf_conntrack \
      nft_ct nft_nat nft_reject_inet nf_reject_ipv4 nf_reject_ipv6; do
      modprobe "$one" || echo "chock guest: $one is not a module here"
    done

    # **A fault in a tool call says where it was.** Without this the kernel drops
    # an unhandled user fault silently, and a call that dies on a signal reaches
    # the host as a number with nothing behind it.
    echo 1 > /proc/sys/debug/exception-trace || true

    # For the record, in the one place a person diagnosing a guest reads.
    busybox uname -a

    busybox mount -t virtiofs ${tag} ${shares}

    # `chock guest` opens the vsock itself and needs nothing on its standard
    # input. It is the last thing this script does, so a guest is one process
    # once it is up.
    exec /bin/chock guest
  '';

  init = hostPkgs.writeScript "chock-guest-init" ''
    #!/bin/busybox sh
    set -eu

    # **The console and not the kernel log.** A guest that failed to come up says why
    # here and nowhere else, and `/dev/kmsg` takes each write as its own record: a
    # trace sent there arrives one word to a line, interleaved with the kernel's own,
    # and reads as though it stopped partway.
    busybox mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
    exec >/dev/console 2>&1
    set -x

    ending() {
      busybox poweroff -f
    }
    trap ending EXIT

    busybox mkdir -p /newroot
    busybox mount -t tmpfs tmpfs /newroot

    # **`/nix` as well as `/bin` and `/lib`.** Everything in those two is a
    # symbolic link into a store inside the image, so a copy without the store is
    # a root of links to nothing.
    for one in /bin /lib /nix /var /init; do
      [ -e "$one" ] && busybox cp -a "$one" /newroot/
    done

    # **Every mount point is made after the copy.** `makeInitrdNG` puts a
    # directory in the image only when a file goes in it, so none of these is
    # there, and making them first would put the copy inside one of them.
    busybox mkdir -p /newroot/proc /newroot/sys /newroot/dev \
      /newroot/tmp /newroot/run /newroot${shares}

    # **`/stage-2` and not the store path.** `makeInitrdNG` puts in the image what
    # `contents` lists and nothing else, so a store path named only inside this
    # script is not there: the guest powered off on `cp: can't stat`.
    busybox cp /stage-2 /newroot/stage-2

    # `switch_root` removes what is left of the initramfs, so nothing above this
    # line is there afterwards.
    exec busybox switch_root /newroot /stage-2
  '';

  initrd = hostPkgs.makeInitrdNG {
    # Uncompressed: the kernel spends no time on it and Mirage places it as one
    # measured blob.
    compressor = "cat";
    contents = [
      {
        target = "/init";
        source = init;
      }
      {
        target = "/stage-2";
        source = stage_two;
      }
      {
        target = "/bin/busybox";
        source = "${busybox}/bin/busybox";
      }
      {
        target = "/bin/modprobe";
        source = "${guestPkgs.kmod}/bin/modprobe";
      }
      {
        target = "/lib/modules";
        source = "${modules}/lib/modules";
      }
      # **A plain target, never the store path itself.** Given the store path as
      # both, `makeInitrdNG` writes a symlink at that path pointing at that path:
      # the initrd then holds chock's whole closure, glibc and all, and a link to
      # nothing where the binary should be. The guest ran, mounted its share, and
      # answered 127 on the exec.
      {
        target = "/bin/chock";
        source = "${chock}/bin/chock";
      }
    ];
  };
in
{
  inherit kernel initrd;

  # What the host has to tell Mirage, kept beside the things it describes so a
  # caller reads one place. `chock guest` dials `port` itself.
  boot = {
    inherit tag shares;
    cmdline = "console=ttyAMA0 loglevel=7 init=/init";
    port = 1024;
    # What `.sandbox.kernel` in `config.zon` is set to. The derivation is a
    # directory: the image inside it is what a guest boots.
    image = "${kernel}/Image";
  };

  meta = {
    description = "The kernel and initrd a Chock microVM guest boots";
    platforms = lib.platforms.linux;
  };
}
