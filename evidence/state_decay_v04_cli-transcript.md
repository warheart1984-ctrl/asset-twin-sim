# State-Decay Test Spec v0.4 CLI transcript

Command executed:

```bash
.venv/bin/python -m app.asset_twin.state_decay_v04_harness --seed shareable-v04
```

Captured stdout:

```text
State-Decay Test Spec v0.4
simulation-only; discrete clock; Ed25519 permit; explicit action trace
seed=shareable-v04
oracle_loaded_before_execution=True
oracle_fixture=state_decay_v04_oracle.py oracle_sha256=8052b2bacb53266adb355c767c6a98e17e1ba6f469eab4109151c953f234134b
conditions=required_ground_bearing:100.0 safety_factor:1.2 planned_outrigger_load:100.0 outrigger_tolerance:5.0 freshness_window:2

case=ground_bearing_change_only pass=True
oracle_match=True action_boundary_match=True
step | state | tick | baseline | gated | oracle
1 | A | 0 | RUN | RUN | RUN/RUN
2 | B | 1 | RUN | HOLD | RUN/HOLD
3 | B | 2 | RUN | — | RUN/—
steps_run baseline=3 gated=1
action_invocations baseline=[1, 2, 3] gated=[1]
gated_step_2_action_invoked=False
evidence_verify baseline=(True, []) gated=(True, [])
tamper_verify=(False, ['entry 2: digest mismatch'])
evidence_hashes baseline=['sha256:f87524d46d94642ec7202b160c3790afc1ba94e1e4fd5af884d0bb68fd8484e3', 'sha256:1e194bd6f0a7d16c813c7a3e8b2108ab07bc38d802801fd6e289dda05c7486b9', 'sha256:99c85b785e9dae3a476a1f99c5a986751ff4d2fffb397b2246f9db229cc397a1', 'sha256:9bc79e24458b5041935d5aec39933d20069a9c0f823a615163b20329ab92bc89', 'sha256:cb33453a340915b8ba44e1130e6fea5d3be7f3596f57e956972af7b7c20a5a0e', 'sha256:582ec8025db008dab577103dc8b361c050514c0943be3dd958d601b10329d46e', 'sha256:c597f8d1d996fe2770b2ddf4fa0b7e8c98345c34a136f3d74305c9ef96690286', 'sha256:3328d6dfffa90c76fa384f2fc358e130cfc66f67829453f6503379169f35a1f5', 'sha256:6ce1e7b751d5d457ea6dafd07b0f09ffe876f7d225e661f006e9bc191c3183fd', 'sha256:c8c7261680b5adf69e225d5ece386d774dc294e1189f5e369364aadd03a808e5', 'sha256:5d5eac39725dc5ee02a7b7b4c890dbac6bdb591b1014d46029f50a7598a56c25', 'sha256:f487659452d39f880c8b89419be0428c9079e999a9b5a9fd62e3d0c19f5c3b69']
evidence_hashes gated=['sha256:26b4548bd0f22de956a0b76f202463a3bda75e3d20d6657706f2cac0dd85ddf8', 'sha256:a59e9d258fc238402eef6527f0ff1eaf2ca87c388d77665b7472086c8d5c5083', 'sha256:235a4a7aefafb5853220d817ce453846e1b59126b37356d2c223d930315b4eab', 'sha256:3150b38d277599a66d8a91971c94f530687fc550ff7cec0d7aca1a4a4edda280', 'sha256:b99b655289bb1c88e807a18dd0568332bc5dff099df5c005b0640f45e9b5cb9a', 'sha256:ccdced4828da03540f215003873455b811f1c4b5c16ef374794d277a80ad2d99', 'sha256:11ae62327f2bae665919638cbcad789a810bbf05802c0752acc30d9ba2b9c457', 'sha256:0649ebcbc3afedb6d57a7549e754ca73bb1700f7eb595663792f14652fdccd49']

case=ground_bearing_control pass=True
oracle_match=True action_boundary_match=True
step | state | tick | baseline | gated | oracle
1 | A | 0 | RUN | RUN | RUN/RUN
2 | B | 1 | RUN | RUN | RUN/RUN
3 | B | 2 | RUN | RUN | RUN/RUN
steps_run baseline=3 gated=3
action_invocations baseline=[1, 2, 3] gated=[1, 2, 3]
gated_step_2_action_invoked=True
evidence_verify baseline=(True, []) gated=(True, [])
tamper_verify=(False, ['entry 2: digest mismatch'])
evidence_hashes baseline=['sha256:4ef83d0b870f65efd77b0506e1c00cb8bdd80a75a95d246bc61bb5ad37aa412b', 'sha256:9b01e301db6f78e33c6e051fd9e069d8081b57017ba49b8163a1eb9b2922c325', 'sha256:03f6b319e74c059c5204159e44cf81dd290ad1ce7e287ef36c8405a30e347dd4', 'sha256:e30d37380695eb47c5a23039844cc7349c8dbab9989eefda864f758d0169ac18', 'sha256:43f4cca41008d42ac641a2af556bbe93104682e39419bd1cf1d7b5a442b02cb7', 'sha256:0083d2021a0ba0c999eb419db248e01751298a5b0e2df42c58df89ac8117d31a', 'sha256:f5b9a286bd2362345dc3227640ae4f39d8e102389c0d289112042a70b390c1af', 'sha256:8e0462b1384c251dc70d1f282bbd33633c899a706db9a9484ff48dce4e4f9aca', 'sha256:a5e032253eb7ac668f27c0f29df92d12a61c36d36daec63329333a93c9b7a41f', 'sha256:211422fc6ea881e3c84566dec75d7880d6d0c7a0f3283df8b8fdb3cedeabe676', 'sha256:69a6f5a66739fc7fe89b79fe57c1c197ff6a65d95228a234df3d403c01c95c26', 'sha256:939a7a14218af3cf5af1f235fcc2ae5e4807708c119cde544f90d9cbf9ed6445']
evidence_hashes gated=['sha256:37cd6900617b63e3b5204833190a89cdc34ba4dbcc6de343ba192cc7e795cd93', 'sha256:e5722671d3083659c71c1b13b616738e6e19251fd4bb3c3bbed94cf58c4d4f81', 'sha256:2e335b5e1448e1d8ee9ca8ca651f85b0189e0a25bdc9d239be00ee8fa91ec515', 'sha256:74d1fe4e245d879283dd95a7bd99e4cdd63cded095db7e183fc6bd29b25628ef', 'sha256:5d636a432841c565553535576977c3417063bb604872e320f14c2e8c0ec70bc1', 'sha256:89abb006fef265c7ecbf83695fcbb75b1d14e77e279672d487754d8fca01f895', 'sha256:99c2cda739ebeadb1b99320f39ad64d91195724da973a3ebf46763823a22385c', 'sha256:990ca833b49cebb2c89576f789a03f997a315464c1001e2518dbaf03b653f436', 'sha256:19f461198863fc0b47036b2074adff7ac5bd5beaf77e36e3307ea26ba4863250', 'sha256:0a9ed7541ec4315059d45c04f37b5bc3434ca2d2ce6c1b1bd5765f94fcf69eca', 'sha256:97888507b03719f0185c7d99ff017959e2c5e9e5721a42e9347e548e2fe196a9', 'sha256:1c2e171fa296dbd074909fe01530652b27a4450ffe53d55fd16b04e3d56d8c48']

case=outrigger_load_change_only pass=True
oracle_match=True action_boundary_match=True
step | state | tick | baseline | gated | oracle
1 | A | 0 | RUN | RUN | RUN/RUN
2 | B | 1 | RUN | HOLD | RUN/HOLD
3 | B | 2 | RUN | — | RUN/—
steps_run baseline=3 gated=1
action_invocations baseline=[1, 2, 3] gated=[1]
gated_step_2_action_invoked=False
evidence_verify baseline=(True, []) gated=(True, [])
tamper_verify=(False, ['entry 2: digest mismatch'])
evidence_hashes baseline=['sha256:4d589ad55b3a1492d9cc955ef452a3643f6914094617f664c5f1319c7a5eec74', 'sha256:46492fe3e858a7f1caf05608fa6dde7cdf032964c28c8c2b6f13f3169c3671bf', 'sha256:5f5390cdebf10bcb81ead2cfef0f4296b92099ec7a1e892793c5d9538eecc360', 'sha256:a31ee6714b6de35d7e8e239fcebe4de12a1ce3ce5072f18588731c3e52b6f80b', 'sha256:06559d46d54e2aef71f6c4546b14079b67c53431ec3960a3c6a71e9fa0f8f071', 'sha256:a049804098123b81e662f002cb4b170941c35b879cae22c45e39aaa0cebc53c2', 'sha256:51f7f1d2a6b07bb0bf04069f59a861092c63b0af4ddd44d9ffd750a33ee7555f', 'sha256:38f9f9834fe3e970d9c33efe82da7bcae296b53ea6b57becec7e0f0a405a96b3', 'sha256:cf91eb1b815c05e615d0089deae5e5307fb9ff6c99f3dd960e702d4c3f7e252f', 'sha256:0ae5c48264f04d09623a6452d60fed28b32d03319652a5d6145085c60c291cc7', 'sha256:b38058d12d6fae549a9c89c5da5133897db291e39b2dc374cef7dbbba751ef77', 'sha256:e684edab73e02b3cd2bbe8b79b998ec4ba43de3eab501452065f4e12ad35fc9c']
evidence_hashes gated=['sha256:95dcecdf715d467bf99fe12013ac448e3e0810db7390f0f294f6734755591474', 'sha256:277efd9cd15d7efb09d390ddee1b17d205fba33e9b6c51897039497404299097', 'sha256:49e7eac6567082d2de8ada09ac8e844125715dc5cea8dfae2174b65d307874bd', 'sha256:86904195d47158c7370c99b2a9f467e1e549218bbdce6d239c2d8aa263e010c8', 'sha256:2f6c98992f5fa3954b2334f86cfe63df4d98de6cb168ebe196217a819958c86c', 'sha256:9e6480f31d2a2fba5daef62fe7a20521243ae3d0b2f69e1035e848f984a2cc8b', 'sha256:208ef729df11975486903d9a2e8651c9b3dfc1fb645c9ce91b839fb913c3f247', 'sha256:1891f53f5c4de75597affd237f2fd3ba882e004a39652fe858059b69f60a7282']

case=outrigger_load_control pass=True
oracle_match=True action_boundary_match=True
step | state | tick | baseline | gated | oracle
1 | A | 0 | RUN | RUN | RUN/RUN
2 | B | 1 | RUN | RUN | RUN/RUN
3 | B | 2 | RUN | RUN | RUN/RUN
steps_run baseline=3 gated=3
action_invocations baseline=[1, 2, 3] gated=[1, 2, 3]
gated_step_2_action_invoked=True
evidence_verify baseline=(True, []) gated=(True, [])
tamper_verify=(False, ['entry 2: digest mismatch'])
evidence_hashes baseline=['sha256:05be6cdbcda68f9d4204d275e3140da0eae8d8182494fb2a374914bdd6f2e403', 'sha256:7742fd3b95a14fd6f88fa21c70dd9debede05fea43c180d524abcc9dc7298e6a', 'sha256:589c3742bb5cde6342860ef9d4b80474b3b50470453100cd2a162a3b8369c7e4', 'sha256:f483d14ec6787c8b4497d9fc18feba69aea1b684c006d0020fa4a2ba4616d2b9', 'sha256:238694c02f12cbafa3935761fcd8f847060df07611e41e7e487c2e745a96d89c', 'sha256:a8fc773c54e46fcf5893b0fdb593156f8eed6b5c5984b90530d7bb9e4e1b0b0a', 'sha256:73dc88b8dd55f2c61bbb7f1a9d49c55e265ecb77f9d46db84a30428857b1c904', 'sha256:9a3f5d2f4a9823e28ebf3f31a376cb05a17f9413aaae2b62f9982a181b2d7e1c', 'sha256:9a23b3d67df1034254ba3bff687d22ea1e063352f359a6ec63a19665ada492fc', 'sha256:02b21472e1fa6dd3d122995b6a4034f4d13dccbe129dae262a45437e76d039f8', 'sha256:34071a04e0f83170facf2d525693027113d18fdda7edb186ca77a6b6ce9ee869', 'sha256:ed04daacd7b04ae2e25be238971b6f151238c3c4eb861fea2718c74ba64e9dfe']
evidence_hashes gated=['sha256:3d76fbf49de797adefb6e21fc0f7982d77d5fbf6528427268e472ee1cb1286f4', 'sha256:6585410f93da4fa734b77d650282ac684f105389dc2a80bea55e2a1b7f1fe4b6', 'sha256:583fad3dea35a8e1fd95645ed633639f607e58f34c91479922bfee5529063c80', 'sha256:0bd8a13eeae41ed70f4364dc366771d9bc461e055f5af5de0676604ac5728fad', 'sha256:805e77a55ff7247c71fe6ffd82795602985963335ed0e11bc4b5d1a25fdd86f2', 'sha256:efd9a27f6f83d821c60b041d0714e484d163862e0475ba7137aab0814a8562fb', 'sha256:4afcf36239ba38a9049ad6e4e404d1ca60201a895f7a50db52149cd8a35521de', 'sha256:70e48c3ced641c6f9fc0b4b9500b31ff11e580c72be7e02e7f16b8d8010071a2', 'sha256:5ad5217679cd3d28ea0c22aa363279d85177594e8ba081ad1e8de605129d5961', 'sha256:1b396cd8b65b70304e89f5582fcf531cee1a887443d410dc32fbb91b3fe76587', 'sha256:cf72a2ae3f32ea853f2599594e2cc7b3870e30bf8f60afea81007815d71145a1', 'sha256:325a5cdc6c13dd3dcee5814b16af80402aa15793afda1ba40feef8db38d9dbfd']

oracle_all_pass=True
reproducible=True
```

This transcript is recorded as generated by the harness. The oracle was committed before this command was executed.
