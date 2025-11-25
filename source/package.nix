{
  pkgs,
  card ? false,
}:
pkgs.callPackage (
  {
    lib,
    rustPlatform,
    pkg-config,
    nettle,
    cargo,
    rustc,
    capnproto,
    pcsclite,
    sqlite,
  }:
  let
    stageWorkspace =
      name: files:
      let
        linkLines = lib.strings.concatStringsSep "\n" (
          map (f: ''
            filename=$(${pkgs.coreutils}/bin/basename ${f} | ${pkgs.gnused}/bin/sed -e 's/[^-]*-//')
            ${pkgs.coreutils}/bin/cp -r ${f} $filename
          '') files
        );
      in
      pkgs.runCommand "stage-rust-workspace-${name}" { } ''
        set -xeu -o pipefail
        ${pkgs.coreutils}/bin/mkdir $out
        cd $out
        ${linkLines}
      '';
    workspace = stageWorkspace "spaghettinuum-native" [
      ./nixbuild/Cargo.toml
      ./native/Cargo.lock
      ./native
      ./shared
    ];
    fenix =
      import
        (fetchTarball "https://github.com/nix-community/fenix/archive/1a79901b0e37ca189944e24d9601c8426675de50.zip")
        { };
    toolchain = fenix.combine [
      fenix.latest.rustc
      fenix.latest.cargo
    ];
    naersk =
      pkgs.callPackage
        (fetchTarball "https://github.com/nix-community/naersk/archive/378614f37a6bee5a3f2ef4f825a73d948d3ae921.zip")
        {
          rustc = toolchain;
          cargo = toolchain;
        };
  in
  naersk.buildPackage {
    pname = "spaghettinuum";
    version = "0.0.0";
    src = workspace;
    buildFeatures =
      [ ]
      ++ (lib.optionals card [
        "card"
      ]);
    buildInputs = [
      sqlite
    ]
    ++ (lib.optionals card [
      nettle
      pcsclite
      sqlite
    ]);
    nativeBuildInputs = [
      pkg-config
      cargo
      rustc
      rustPlatform.bindgenHook
      capnproto
    ];
  }
) { }
