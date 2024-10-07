{ pkgs ? import <nixpkgs> {} }:
  pkgs.mkShell {
    nativeBuildInputs = with pkgs.buildPackages; [
      ruby_3_3
      bundix
      autoconf
      automake
      libtool
      secp256k1
    ];
  }
