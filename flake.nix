{
  description = "Felidae blockchain application for WEBCAT infrastructure";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-25.11";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane = {
      url = "github:ipetkov/crane";
      # inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay, crane }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

      # Read version information from Cargo workspace
      # cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);
      cargoLock = builtins.fromTOML (builtins.readFile ./Cargo.lock);

      # Extract felidae version from Cargo.toml workspace. We inspect the specific crate,
      # rather than the workspace, because the workspace currently doesn't define versions.
      # Reusing the Cargo-specified version number ensures there's only a single point of update
      # when bumping versions.
      felidaeCrateToml = builtins.fromTOML (builtins.readFile ./crates/felidae/Cargo.toml);
      felidaeVersion = felidaeCrateToml.package.version;

      # CometBFT source configuration.
      # To update the cometbft hash values, run:
      # nix-prefetch-git --url https://github.com/cometbft/cometbft --rev <tag>
      # and review the output.
      cometbftVersion = "0.38.21";
      cometbftRev = "c56d64ec53bd72dfd99a5b0f5cb3eaad224a7021"; # v0.38.21
      cometbftSrcHash = "sha256-ehfFxnUBRCXFrlkpvB0UMmnNPjYEY1T1sTHbjUB+70g=";
      cometbftVendorHash = "sha256-BFm+AimN+fdUPz3+MNIvJyqp8dsn5JjNaipnYsHZiC8=";
      cometbftSrc = pkgs.fetchFromGitHub {
        owner = "cometbft";
        repo = "cometbft";
        rev = cometbftRev;
        hash = cometbftSrcHash;
      };

      # Rust toolchain
      rustToolchain = pkgs.rust-bin.stable.latest.default.override {
        extensions = [ "rust-src" "rust-analyzer" ];
        targets = [ "wasm32-unknown-unknown" ];
      };

      # Crane library for workspace builds with custom toolchain
      craneLib = (crane.mkLib pkgs).overrideToolchain (_: rustToolchain);

      # Source filtering for Rust workspace (improves cache hit rates)
      # Include .proto files which are needed by build scripts
      src = pkgs.lib.cleanSourceWith {
        src = craneLib.path ./.;
        filter = path: type:
          (craneLib.filterCargoSources path type)
          || (builtins.match ".*proto$" path != null);
      };

      # Common arguments shared across all crane builds
      commonCraneArgs = {
        inherit src;

        nativeBuildInputs = commonNativeBuildInputs;
        buildInputs = commonBuildInputs;

        LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
        doCheck = false;
      };

      # Build workspace libraries once to reuse artifacts across packages
      # We build the full libraries (not buildDepsOnly) because felidae-proto has a build script
      # that depends on .proto source files, which aren't available in buildDepsOnly's dummy sources
      cargoArtifacts = craneLib.buildPackage (commonCraneArgs // {
        pname = "felidae-workspace-deps";
        version = felidaeVersion;
        cargoArtifacts = null;
        # Build only workspace libraries to create reusable artifacts with build script outputs
        cargoBuildCommand = "cargo build --release --workspace --lib";
        # Don't install binaries, we just want the build artifacts
        installPhaseCommand = "mkdir -p $out";
      });

      # Separate crane library for wasm-bindgen-cli (doesn't need custom toolchain)
      craneLibWasmBindgen = crane.mkLib pkgs;

      # wasm-bindgen-cli config.  We extract the wasm-bindgen version from the Cargo lock file,
      # to ensure the nix build uses the precise matching version, otherwise the interface
      # specs will drift.
      wasmBindgenVersion =
        let
          wasmBindgenPkg = builtins.head (builtins.filter
            (pkg: pkg.name == "wasm-bindgen")
            cargoLock.package);
        in wasmBindgenPkg.version;

      wasm-bindgen-cli = craneLibWasmBindgen.buildPackage {
        pname = "wasm-bindgen-cli";
        version = wasmBindgenVersion;

        src = pkgs.fetchCrate {
          pname = "wasm-bindgen-cli";
          version = wasmBindgenVersion;
          hash = "sha256-9kW+a7IreBcZ3dlUdsXjTKnclVW1C1TocYfY8gUgewE=";
        };

        nativeBuildInputs = [ pkgs.pkg-config ];
        buildInputs = [ pkgs.openssl ];

        doCheck = false;

        meta = with pkgs.lib; {
          description = "Facilitating high-level interactions between wasm modules and JavaScript";
          homepage = "https://github.com/rustwasm/wasm-bindgen";
          license = with pkgs.lib.licenses; [ asl20 mit ];
          mainProgram = "wasm-bindgen";
        };
      };

      # Declare build inputs as vars, so multiple packages can reference them.
      # The native inputs are required on the build host.
      commonBuildInputs = with pkgs; [
        openssl
        libclang.lib
      ];
      commonNativeBuildInputs = with pkgs; [
        rustToolchain
        pkg-config
        clang
        protobuf
        protoc-gen-go
      ];

      in
      {
        packages = {
        # CometBFT build
        cometbft = pkgs.buildGoModule {
          pname = "cometbft";
          version = cometbftVersion;

          src = cometbftSrc;
          vendorHash = cometbftVendorHash;
          subPackages = [ "cmd/cometbft" ];
          buildInputs = [ pkgs.protobuf ];
          ldflags = [
            "-s"
            "-w"
            "-X github.com/cometbft/cometbft/version.TMCoreSemVer=${cometbftVersion}"
          ];

          meta = with pkgs.lib; {
            description = "CometBFT (a.k.a. Tendermint Core)";
            homepage = "https://github.com/cometbft/cometbft";
            license = licenses.asl20;
            mainProgram = "cometbft";
          };
        };

        # Felidae Rust workspace build
        felidae = craneLib.buildPackage (commonCraneArgs // {
          inherit cargoArtifacts;

          pname = "felidae";
          version = felidaeVersion;

          # Build all workspace binaries
          cargoBuildFlags = [ "--workspace" "--bins" ];

          meta = with pkgs.lib; {
            description = "Felidae blockchain application for WEBCAT infrastructure";
            license = licenses.mit;
          };
        });

        # WASM package for felidae-oracle
        felidae-oracle-wasm =
          let
            # Build the WASM binary using crane
            wasmBinary = craneLib.buildPackage (commonCraneArgs // {
              inherit cargoArtifacts;

              pname = "felidae-oracle-wasm-binary";
              version = felidaeVersion;

              cargoBuildFlags = [ "--package" "felidae-oracle" ];
              cargoExtraArgs = "--target wasm32-unknown-unknown";

              # We're building WASM, not cargo binaries
              doNotPostBuildInstallCargoBinaries = true;

              # Explicitly set build phase to use release mode
              buildPhaseCargoCommand = ''
                cargo build --release \
                  --target wasm32-unknown-unknown \
                  --package felidae-oracle
              '';

              # Override install phase to extract WASM file
              installPhaseCommand = ''
                mkdir -p $out/lib
                cp target/wasm32-unknown-unknown/release/felidae_oracle.wasm $out/lib/
              '';
            });
          in

          # Process with wasm-bindgen to generate JS bindings
          # We must use precisely the version of `wasm-bindgen-cli` that's specified in Cargo.lock,
          # otherwise the spec versions will not match, and `wasm-bindgen-cli` will error out.
          pkgs.stdenv.mkDerivation {
            pname = "felidae-oracle-wasm";
            # TODO: should felidae-oracle-wasm be versioned independently of the other felidae bins?
            version = felidaeVersion;

            src = wasmBinary;

            nativeBuildInputs = [ wasm-bindgen-cli ];

            buildPhase = ''
              wasm-bindgen \
                --target web \
                --out-dir pkg \
                lib/felidae_oracle.wasm
            '';

            installPhase = ''
              mkdir -p $out
              cp -r pkg/* $out/
            '';

            meta = with pkgs.lib; {
              description = "Felidae oracle WASM package";
              license = licenses.mit;
            };
          };

          # Frontend web application
          frontend = pkgs.buildNpmPackage {
            pname = "webcat-frontend";
            version = "1.0.0";

            src = ./frontend;

            npmDepsHash = "sha256-q/G1EgDDGLaj3ku169XLHw5NGIKdSTCWmgZiPVmmaRc=";

            # No build step needed - pure runtime application
            dontNpmBuild = true;

            installPhase = ''
              mkdir -p $out/lib/webcat-frontend
              cp -r server.js public $out/lib/webcat-frontend/
              cp -r node_modules $out/lib/webcat-frontend/

              mkdir -p $out/bin
              cat > $out/bin/webcat-frontend <<EOF
              #!${pkgs.bash}/bin/bash
              exec ${pkgs.nodejs}/bin/node $out/lib/webcat-frontend/server.js "\$@"
              EOF
              chmod +x $out/bin/webcat-frontend
            '';

            meta = with pkgs.lib; {
              description = "Frontend webapp for WEBCAT domain enrollment requests";
              license = licenses.mit;
              mainProgram = "webcat-frontend";
            };
          };

          # OCI container image. Can be built via:
          #
          #   nix build .#container
          #   podman load < result
          #   podman run "localhost/felidae:$(nix eval --raw .#felidae.version)"
          #
          container = pkgs.dockerTools.buildImage {
            name = "felidae";
            tag = felidaeVersion;

            copyToRoot = pkgs.buildEnv {
              name = "image-root";
              paths = [
                self.packages.${system}.felidae
                self.packages.${system}.cometbft
                pkgs.bashInteractive
                pkgs.coreutils
              ];
              pathsToLink = [ "/bin" ];
            };

            config = {
              Cmd = [ "/bin/felidae" ];
              Env = [
                "PATH=/bin"
              ];
            };
          };

          # Combined default package with both felidae and cometbft
          default = pkgs.symlinkJoin {
            name = "felidae-with-cometbft-${felidaeVersion}";
            paths = [
              self.packages.${system}.felidae
              self.packages.${system}.cometbft
            ];
            meta = with pkgs.lib; {
              description = "Felidae blockchain application with CometBFT";
              license = licenses.mit;
            };
          };
        };

        # Development shell
        devShells.default = pkgs.mkShell {
          buildInputs = commonBuildInputs ++ commonNativeBuildInputs ++ [
            # Additional Rust dev tools
            pkgs.cargo-watch
            pkgs.cargo-edit
            pkgs.cargo-nextest
            pkgs.wasm-pack
            wasm-bindgen-cli  # Use our custom version that matches Cargo.lock

            # CometBFT binary (pre-built from flake)
            self.packages.${system}.cometbft
            # nix tooling to fetch hashes for remote packages
            pkgs.nix-prefetch-scripts

            # Go toolchain for CometBFT development
            pkgs.go_1_24

            # Additional protobuf tools
            pkgs.protoc-gen-go-grpc

            # Build tools
            pkgs.gnumake

            # Development tools
            pkgs.just
            pkgs.git

            # Shell utilities
            pkgs.jq
            pkgs.curl

            # Process management for integration testing
            pkgs.process-compose

            # Node.js for frontend development
            pkgs.nodejs
          ];

          # clang must be available for builds
          LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
        };
    });
}
