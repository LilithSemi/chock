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

  # Chock's own binary, for the guest. `chock guest` is a subcommand of it: see
  # `src/guest.zig`, and `test/plugin/one_binary.zig` for why there is no second
  # program to build here.
  chock = guestPkgs.chock;

  # Where the one virtiofs mount goes, and the tag Mirage exports it under. Each
  # directory the host offers appears as a name inside it.
  shares = "/mnt/shares";
  tag = "mirage";

  init = hostPkgs.writeScript "chock-guest-init" ''
    #!/bin/busybox sh
    set -eu

    # Everything before the sandbox is on the kernel log, because a guest that
    # failed to come up says why there and nowhere else.
    busybox mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
    exec >/dev/kmsg 2>&1
    set -x

    ending() {
      busybox poweroff -f
    }
    trap ending EXIT

    busybox mount -t proc none /proc
    busybox mount -t sysfs none /sys
    busybox mkdir -p /dev/shm
    busybox mount -t tmpfs tmpfs /dev/shm -o rw,nosuid,nodev

    # The channel to whoever started this guest, and the one mount every share
    # arrives in. Nothing else is loaded: a module a guest does not need is a
    # driver a guest does not have.
    modprobe vsock
    modprobe vmw_vsock_virtio_transport
    modprobe virtio_pci
    modprobe virtio_mmio
    modprobe virtiofs

    busybox mkdir -p ${shares}
    busybox mount -t virtiofs ${tag} ${shares}

    # `chock guest` opens the vsock itself and needs nothing on its standard
    # input. It is the last thing this script does, so a guest is one process
    # once it is up.
    exec ${chock}/bin/chock guest
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
        target = "/bin/busybox";
        source = "${busybox}/bin/busybox";
      }
      {
        target = "/bin/modprobe";
        source = "${guestPkgs.kmod}/bin/modprobe";
      }
      {
        target = "/lib/modules";
        source = "${kernel.modules}/lib/modules";
      }
      {
        target = "${chock}/bin/chock";
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
    cmdline = "console=ttyAMA0 init=/init";
    port = 1024;
  };

  meta = {
    description = "The kernel and initrd a Chock microVM guest boots";
    platforms = lib.platforms.linux;
  };
}
