# Volumesetup

This is a small program to automatically set up attached storage on cloud or baremetal hosts at boot.

It looks for an existing disk matching a well-known UUID and either unlocks and mounts it or formats and mounts the most suitable unused (not mounted) physical storage it finds.

It has three modes:

- No encryption - provision an unencrypted disk

- Shared image encryption - credentials are directly encrypt/decrypt the drive, and the image itself contains no encrypted data

  Credentials can be provided programmatically (file/stdin) or interactively (systemd-ask-password)

- Private image encryption - the image contains an encrypted key used to encrypt/decrypt the drive

  At the moment, credentials must be provided interactively (via gpg smartcard, via NFC or USB).

  Additional encrypted data can be included in the image which will be decrypted at unlock.

## Installation

### Nix

Either have it run automatically like:

```nix
imports = [
  ./volumesetup/source/module.nix
];
config = {
  volumesetup.enable = true;
  volumesetup.debug = true;
  volumesetup.encryption = "private-image";
  volumesetup.encryptionPrivateImageKeyfile = "${./smartcard_keyfile}";
  volumesetup.encryptionPrivateImageMode = "smartcard";
  volumesetup.encryptionPrivateImageSmartcardPinMode = "factory-default";
};
```

Or import the package and call it yourself:

```nix
let volumesetup = (import ./volumesetup/source/package.nix { pkgs = pkgs; }); in "${volumesetup}/bin/volumesetup ..."
```

### Other systems

Clone the repo and build it with `cargo build`. For smartcard support you need to enable the feature `smartcard`.

### Smartcard

Make sure the system has `pcscd` running and the correct `pcsc` drivers for your smartcard reader. You can test the reader with `opgpcard list`. `pscs_scan` and `pcsc-spy` may also help.

Any number of smartcards can be used to unlock the volume. To use smartcard you need to prepare a keyfile encrypted with all keys you want to allow to unlock it:

1. Get the ASCII Armored public keys (`person1.pubkey`, `person2.pubkey`, etc) for all keys you want to be able to unlock with

2. Create a disk key

   ```
   pwgen --symbols --secure 100 1 > disk.plaintext
   ```

   Make sure to back this up in case you want to replace keys in the future.

3. Encrypt the disk key, using `sq` or another GPG client

   ```
   sq encrypt -o disk.key --recipient-file person1.pubkey --recipient-file person2.pubkey ... disk.plaintext
   ```

4. Place the file in the system image and run `volumesetup --encryption private-image --key /path/to/disk.key --key-mode smartcard text` at boot.

#### Nix

You can also do it as part of your system build, if you're building a disk image on a secured build host, with something like this:

```nix
{
    imports = [ ./path/to/volumesetup/source/module.nix ];
    config = {
        volumesetup.enable = true;
        volumesetup.encryption = "private-image";
        volumesetup.encryptionPrivateImageKeyfile =
            let key = derivation {
                name = "volumesetup-key";
                builder = "${pkgs.bash}/bin/bash";
                args = [(pkgs.writeText "volumesetup-key-script" ''
                    ${pkgs.sequoia-sq}/bin/sq \
                        -o $out \
                        --recipient-file ${./person1.pubkey} \
                        --recipient-file ${./person2.pubkey} \
                        ${./disk.plaintext} \
                        ;
                '')];
            }; in "${key}";
        volumesetup.encryptionPrivateImageKeyMode = "smartcard";
    };
}
```

### Private-image additional decryption

When using private-image mode an additional file can be decrypted by the key. This file could contain credentials or other non-dynamic private data. The file is [age](https://github.com/C2SP/C2SP/blob/main/age.md) passphrase-encrypted (symmetric).

1. Create the file you want to place in the image, like `decrypt.txt`

2. Encrypt it with `rage --encrypt --passphrase -o decrypt.age decrypt.txt < disk.plaintext`

3. Pass an additional `--decrypt decrypt.age` argument to `volumesetup`

#### Nix

You can also do it with Nix, if you've already configured private-image mode:

```nix
{
    imports = [ ./path/to/volumesetup/source/module.nix ];
    config = {
        volumesetup.encryptionPrivateImageDecrypt =
            let key = derivation {
                name = "volumesetup-decrypt";
                builder = "${pkgs.bash}/bin/bash";
                args = [(pkgs.writeText "volumesetup-decrypt-script" ''
                    ${pkgs.rage}/bin/rage \
                        --encrypt \
                        --passphrase \
                        -o $out \
                        ${./decrypt.plaintext} \
                        < ${./disk.plaintext} \
                        ;
                '')];
            }; in "${key}";
    };
}
```
