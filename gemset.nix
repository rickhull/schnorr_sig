{
  ecdsa = {
    groups = ["default"];
    platforms = [];
    source = {
      remotes = ["https://rubygems.org"];
      sha256 = "0mgcphwb01rgrz1km8ka6f2ixp76dfvs21g76yz7qn3c3dackxxq";
      type = "gem";
    };
    version = "1.2.0";
  };
  ecdsa_ext = {
    dependencies = ["ecdsa"];
    groups = ["default"];
    platforms = [];
    source = {
      remotes = ["https://rubygems.org"];
      sha256 = "1ipvk4my3zw41wnp0cagjnjn4nbk1h5zx62qws7ih6a5dzxqpvnq";
      type = "gem";
    };
    version = "0.5.1";
  };
  mini_portile2 = {
    groups = ["default" "performance"];
    platforms = [{
      engine = "maglev";
    } {
      engine = "ruby";
    }];
    source = {
      remotes = ["https://rubygems.org"];
      sha256 = "1q1f2sdw3y3y9mnym9dhjgsjr72sq975cfg5c4yx7gwv8nmzbvhk";
      type = "gem";
    };
    version = "2.8.7";
  };
  pkg-config = {
    groups = ["default" "performance"];
    platforms = [{
      engine = "maglev";
    } {
      engine = "ruby";
    }];
    source = {
      remotes = ["https://rubygems.org"];
      sha256 = "04wi7n51w42v9s958gfmxwkg5iikq25whacyflpi307517ymlaya";
      type = "gem";
    };
    version = "1.5.6";
  };
  rbsecp256k1 = {
    dependencies = ["mini_portile2" "pkg-config" "rubyzip"];
    groups = ["performance"];
    platforms = [{
      engine = "maglev";
    } {
      engine = "ruby";
    }];
    source = {
      remotes = ["https://rubygems.org"];
      sha256 = "0s8ny5r3ldk0ff0wcx0y55zl5439rjc4fsik1ki3rkvbzhxmd3yk";
      type = "gem";
    };
    version = "6.0.0";
  };
  rubyzip = {
    groups = ["default" "performance"];
    platforms = [{
      engine = "maglev";
    } {
      engine = "ruby";
    }];
    source = {
      remotes = ["https://rubygems.org"];
      sha256 = "0grps9197qyxakbpw02pda59v45lfgbgiyw48i0mq9f2bn9y6mrz";
      type = "gem";
    };
    version = "2.3.2";
  };
  schnorr_sig = {
    dependencies = ["ecdsa_ext"];
    groups = ["default"];
    platforms = [];
    source = {
      path = ./.;
      type = "path";
    };
    version = "1.2.0.1";
  };
}
