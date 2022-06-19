{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
          LIBCLANG_PATH = "${pkgs.llvmPackages_13.libclang.lib}/lib";
          KERNEL_SOURCE = "${pkgs.linuxPackages.kernel.dev}/lib/modules/${pkgs.linuxPackages.kernel.version}";

          nativeBuildInputs = with pkgs; [
            pkgconfig
            llvm_13
            clang_13
            rustup
          ];
          buildInputs = with pkgs; [
            openssl
            zlib
            libxml2
            libelf
            llvm_13.dev
            clang_13
#            linuxPackages.kernel.dev
            linuxHeaders
            glibc.dev
          ];
        
}
