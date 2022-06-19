{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
LIBCLANG_PATH = "${pkgs.llvmPackages_13.libclang.lib}/lib";

          nativeBuildInputs = with pkgs; [
            pkgconfig
            llvm_13.all
            clang_13
            rustup
          ];
          buildInputs = with pkgs; [
            openssl
            zlib
            libxml2
            libelf
            linuxPackages.kernel.dev
            linuxHeaders
            glibc.dev
          ];
       

}
