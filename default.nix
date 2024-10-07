{ pkgs ? import <nixpkgs> {} }:
pkgs.mkShell {
  nativeBuildInputs = with pkgs.buildPackages; [
    ruby_3_3
    autoconf
    automake
    libtool
    secp256k1
  ];
}
