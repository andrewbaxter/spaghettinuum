{ pkgs, card ? false }: pkgs.callPackage
  ({ lib
   , rustPlatform
   , pkg-config
   , nettle
   , cargo
   , rustc
   , capnproto
   , pcsclite
   , sqlite
   }:
  rustPlatform.buildRustPackage {
    pname = "spaghettinuum";
    version = "0.0.0";
    src = ../source;
    # Based on final path element of src
    sourceRoot = "source";
    # For build.rs:
    # Source is copied over with all the files read only for some reason.
    # Make a new tree as the build user and make the files writable.
    preConfigure = ''
      cd ../
      mv source ro
      cp -r ro rw
      chmod -R u+w rw
      cd rw
    '';
    cargoLock = {
      lockFile = ../source/Cargo.lock;
    };
    buildFeatures = [ ] ++ (lib.optionals card [
      "card"
    ]);
    buildInputs = [ sqlite ] ++ (lib.optionals card [
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
  })
{ }
