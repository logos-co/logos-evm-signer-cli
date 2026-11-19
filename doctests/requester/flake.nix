{
  description = "evm_signer_cli_probe — doc-test fixture: the module that asks for a signature.";

  inputs = {
    logos-module-builder.url = "github:logos-co/logos-module-builder";
    # Pinned to the commits that hold a key for an allowance.
    keystore_module = {
      url = "github:logos-co/logos-evm-keystore-module/eb27b23efe84664bcd66b3a8eb5a0eb12095fd50";
      inputs.logos-module-builder.follows = "logos-module-builder";
    };
    signer_manager_module = {
      url = "github:logos-co/logos-signer-manager-module/471fb75e7f4fab96e798c5945998af1f68f2863d";
      inputs.logos-module-builder.follows = "logos-module-builder";
      inputs.keystore_module.follows = "keystore_module";
    };
  };

  outputs = inputs@{ self, logos-module-builder, ... }:
    let
      nixpkgs = logos-module-builder.inputs.nixpkgs;
      systems = [ "aarch64-darwin" "x86_64-darwin" "aarch64-linux" "x86_64-linux" ];
    in
    {
      packages = nixpkgs.lib.genAttrs systems (system:
        (logos-module-builder.lib.mkLogosModule {
          src = ./.;
          configFile = ./metadata.json;
          flakeInputs = inputs;
        }).packages.${system});
    };
}
