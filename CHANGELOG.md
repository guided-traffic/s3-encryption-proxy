## [1.19.2](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.19.1...v1.19.2) (2025-09-11)


### Bug Fixes

* **deps:** Update aws-sdk-go-v2 monorepo ([#39](https://github.com/guided-traffic/s3-encryption-proxy/issues/39)) ([38571fa](https://github.com/guided-traffic/s3-encryption-proxy/commit/38571fa067d435cf6efea277f575aaefacc18914))

## [1.19.1](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.19.0...v1.19.1) (2025-09-10)


### Bug Fixes

* switch to fixed alpine-linux tag ([e07bcd6](https://github.com/guided-traffic/s3-encryption-proxy/commit/e07bcd6924fb6fc16e5b5214d073fa5afa87051c))
* update to fixed alpine linux image tag ([5f1cb2a](https://github.com/guided-traffic/s3-encryption-proxy/commit/5f1cb2aac9aa9f0473f62b1dcaeabe7ce8e63165))

# [1.19.0](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.18.1...v1.19.0) (2025-09-10)


### Bug Fixes

* **deps:** Lock file maintenance ([413a1c4](https://github.com/guided-traffic/s3-encryption-proxy/commit/413a1c46890698e7cdf261bfbfff5f2ace66912d))
* error message ([4038247](https://github.com/guided-traffic/s3-encryption-proxy/commit/4038247f4dd822ea46999bf205d46ef4c295b688))
* linter issues ([90da821](https://github.com/guided-traffic/s3-encryption-proxy/commit/90da8214fb401256d243bf2c953e724e370cb0ce))
* metadata preparation ([f9a794b](https://github.com/guided-traffic/s3-encryption-proxy/commit/f9a794bd6777bcbd4eeeca6081f577fa25e65680))
* move test to integration ([1e5f1e5](https://github.com/guided-traffic/s3-encryption-proxy/commit/1e5f1e517e3d892676a782f7aebe052a3e9a10bf))
* refactor metadata ([8276d63](https://github.com/guided-traffic/s3-encryption-proxy/commit/8276d636ebf9059d084fc7f44547a7f038377726))
* remove some configs ([2af8ae1](https://github.com/guided-traffic/s3-encryption-proxy/commit/2af8ae1d4b02384cdd0057ef0ee05aff932eec20))
* send error http ([26b2463](https://github.com/guided-traffic/s3-encryption-proxy/commit/26b24631b6fba333032aaeeadc963d4c93d404cc))
* switch back to default meta prefix ([c44819f](https://github.com/guided-traffic/s3-encryption-proxy/commit/c44819ff154b395679a26f424339ec8121473f29))
* testing ([76b0831](https://github.com/guided-traffic/s3-encryption-proxy/commit/76b0831618a6a049b3a00d0acdf27b8ee556dabf))
* testing ([7abfc77](https://github.com/guided-traffic/s3-encryption-proxy/commit/7abfc77c01bc1891c85eeba54d7120a0a05bc384))
* testing ([7740852](https://github.com/guided-traffic/s3-encryption-proxy/commit/7740852f148763029e47a1706b9dacf831fb00d1))
* testing ([98db32b](https://github.com/guided-traffic/s3-encryption-proxy/commit/98db32bee1175d23f14cab062e9ba27e94d8d502))
* testing ([46ce5a0](https://github.com/guided-traffic/s3-encryption-proxy/commit/46ce5a0739b26d868796c2e46722014e995d414a))
* working metadata prefix for multipart ([826b79a](https://github.com/guided-traffic/s3-encryption-proxy/commit/826b79a2528dbd6ec2c416394acf607df3a0c396))


### Features

* add kek validation ([cce18d3](https://github.com/guided-traffic/s3-encryption-proxy/commit/cce18d3a90b4ba33632d39480a8ec00b2d388a64))
* add support for http chunk encoding ([76488b4](https://github.com/guided-traffic/s3-encryption-proxy/commit/76488b4f429cc68ac2b03bee7f1a2273a372cee2))
* support for http chunked encoding ([39031e0](https://github.com/guided-traffic/s3-encryption-proxy/commit/39031e08cabef39d41ee157d21bbc263d9345a10))

## [1.18.1](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.18.0...v1.18.1) (2025-09-09)


### Bug Fixes

* **deps:** Lock file maintenance ([cdbef0f](https://github.com/guided-traffic/s3-encryption-proxy/commit/cdbef0f40637656fd6715a3a250bb39f176b4d65))

# [1.18.0](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.17.2...v1.18.0) (2025-09-09)


### Bug Fixes

* **deps:** Update module github.com/spf13/viper to v1.21.0 ([e89ad10](https://github.com/guided-traffic/s3-encryption-proxy/commit/e89ad10d5ae17fee29c58b09cbf497e102647e6c))
* integration tests ([ed14a44](https://github.com/guided-traffic/s3-encryption-proxy/commit/ed14a44c20e021f65f7c9a7cb15404ddfe4828bf))
* integration tests ([3711363](https://github.com/guided-traffic/s3-encryption-proxy/commit/3711363e05df4b118d54e19d96cf0c7725cda09c))
* more test for none provider ([85e6bc4](https://github.com/guided-traffic/s3-encryption-proxy/commit/85e6bc4ea6fb785fc275a3079b17ade0501d3f8f))
* none_provider_test ([3d98471](https://github.com/guided-traffic/s3-encryption-proxy/commit/3d9847149b73f7f7fd539f63071f31cb2f2db437))
* testing ([3f82711](https://github.com/guided-traffic/s3-encryption-proxy/commit/3f82711acfedd341fd3a335c1514975225f82cb4))
* testing ([e598c5b](https://github.com/guided-traffic/s3-encryption-proxy/commit/e598c5b527c8c947529971c55c79c67009e34f0d))
* testing ([8627ca2](https://github.com/guided-traffic/s3-encryption-proxy/commit/8627ca2989c9d7f7077baea7ac4c2e10e988d294))
* update main.go ([5ccc2ee](https://github.com/guided-traffic/s3-encryption-proxy/commit/5ccc2ee50a67e7ab63adfe6aa27fd5f8b5924476))


### Features

* graceful shutdown with request tracking ([45f9895](https://github.com/guided-traffic/s3-encryption-proxy/commit/45f9895b4c10c729f39ea2774cbf6c8f63cc5564))
* Graceful shutdown with request tracking ([e8e2998](https://github.com/guided-traffic/s3-encryption-proxy/commit/e8e29981aef8e50dd334f2bf920611e568ad595c))

## [1.17.2](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.17.1...v1.17.2) (2025-09-09)


### Bug Fixes

* remove provider_alias from metadata ([9137907](https://github.com/guided-traffic/s3-encryption-proxy/commit/9137907d18b8c59b116fa236249e6e7bcd2c7e1a))

## [1.17.1](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.17.0...v1.17.1) (2025-09-09)


### Bug Fixes

* **deps:** Update aws-sdk-go-v2 monorepo ([8205784](https://github.com/guided-traffic/s3-encryption-proxy/commit/8205784ada3bfe2c329e1904415298355ec4df96))

# [1.17.0](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.16.0...v1.17.0) (2025-09-09)


### Bug Fixes

* add performance section ([114fd17](https://github.com/guided-traffic/s3-encryption-proxy/commit/114fd17f606f032a5e7deb999366e5e3f01c14bb))
* dataencryption tests ([6f1e996](https://github.com/guided-traffic/s3-encryption-proxy/commit/6f1e9965d73d412c2938d57a9a86f5bfb643bc19))
* **deps:** Update renovatebot/github-action action to v43.0.11 ([49cbd82](https://github.com/guided-traffic/s3-encryption-proxy/commit/49cbd821c042a758dcf5268084d4087ff803472f))
* encryption methods ([47dcb93](https://github.com/guided-traffic/s3-encryption-proxy/commit/47dcb93756b0e5f80720f105db3ef1f4c7a6c007))
* gosec ([4380dcb](https://github.com/guided-traffic/s3-encryption-proxy/commit/4380dcb8f3bda79b4de4787bf0b6975681aa9d11))
* gosec ([185958a](https://github.com/guided-traffic/s3-encryption-proxy/commit/185958a7cfe935f76b6a6aef123aa95ba7ff0012))
* integration test ([770b7a6](https://github.com/guided-traffic/s3-encryption-proxy/commit/770b7a634b6c0d1425f3e0a429b2493823805995))
* integration testing ([c038304](https://github.com/guided-traffic/s3-encryption-proxy/commit/c038304336905e7e6e0d270d395031ad84943f4c))
* integration tests ([d226abc](https://github.com/guided-traffic/s3-encryption-proxy/commit/d226abca6af295852ff368ba57e94ca530b7e7e2))
* integration tests ([6ca4988](https://github.com/guided-traffic/s3-encryption-proxy/commit/6ca49885add1f87bbecd3a52cdf3da967ab5f597))
* keyencryption tests ([93f9ce9](https://github.com/guided-traffic/s3-encryption-proxy/commit/93f9ce9208fc0bce429b74e4db44610ad5ccf2f8))
* linter ([4e2971c](https://github.com/guided-traffic/s3-encryption-proxy/commit/4e2971c6ffd8759c4fc193e7a33a4a309249076c))
* metadata ([15bc3de](https://github.com/guided-traffic/s3-encryption-proxy/commit/15bc3de3682a9f9cce25856fc4bbd29abc7bafb8))
* metadata improvment ([15e37bc](https://github.com/guided-traffic/s3-encryption-proxy/commit/15e37bc5bdb62ff3d96ccede3537b2ca409e0e67))
* remove direct encryption ([ee09bad](https://github.com/guided-traffic/s3-encryption-proxy/commit/ee09bad7c311af21874c230d0ec98f21de471535))
* remove whitespace ([b59de9d](https://github.com/guided-traffic/s3-encryption-proxy/commit/b59de9db649ec1cabd14d5039de6b8d96547fd1b))
* remove whitespace ([78a3ccd](https://github.com/guided-traffic/s3-encryption-proxy/commit/78a3ccd2a0ee74d24f66a38075ce6effe2b493ff))
* rename kek-name to kek-algorithm ([191385d](https://github.com/guided-traffic/s3-encryption-proxy/commit/191385d2a7f51a11ff29472202fa2d1ef540620c))
* rsa will test rsa pairity ([fb8da36](https://github.com/guided-traffic/s3-encryption-proxy/commit/fb8da36643c4d46cb81f7854555bc9b0b9e1bcf2))
* suppress gosec false positive for AES-CTR counter ([6a0e1a4](https://github.com/guided-traffic/s3-encryption-proxy/commit/6a0e1a4240639cfed8cc5d941076deed3690adcd))
* testing ([a97ac97](https://github.com/guided-traffic/s3-encryption-proxy/commit/a97ac974ddb4225b48e54c5ecb79c634d6c8c438))
* testing ([1a957d9](https://github.com/guided-traffic/s3-encryption-proxy/commit/1a957d9a1d4be7b8928626d79e4a6a9572e0ccf5))
* unit tests ([92b03d0](https://github.com/guided-traffic/s3-encryption-proxy/commit/92b03d04ea8e28381b16c83684d82bdcc17c8b71))
* update unit-tests ([cf415da](https://github.com/guided-traffic/s3-encryption-proxy/commit/cf415da590443230ba7a3da00e19195be6dae991))


### Features

* enable streamingon multipart ([b9646f4](https://github.com/guided-traffic/s3-encryption-proxy/commit/b9646f41cb16e648291b3e6f94922dc6a41ba582))
* integrate everything into the new architecture ([468effb](https://github.com/guided-traffic/s3-encryption-proxy/commit/468effb25d1d248c723b6f796648f144f98e3486))
* memory optimized downlaod streaming ([fad32e4](https://github.com/guided-traffic/s3-encryption-proxy/commit/fad32e44ddb0420e124afaac6b02491215a526e5))
* new key identification ([8d1c361](https://github.com/guided-traffic/s3-encryption-proxy/commit/8d1c3619f4d6b6ebb71ca8b95c6abaa83a625290))
* optimize upload speed ([7b72e3a](https://github.com/guided-traffic/s3-encryption-proxy/commit/7b72e3ae0dbbbfbd4834ae4c3d3e10302addb326))
* refactored encryption structure ([dc3b893](https://github.com/guided-traffic/s3-encryption-proxy/commit/dc3b8938ba45aff4c9e7f9e1dd425e653f0b8144))
* switch to new architekture ([28892f0](https://github.com/guided-traffic/s3-encryption-proxy/commit/28892f0b76fd2590fd1467686b2a9856c494b8c2))

# [1.16.0](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.15.2...v1.16.0) (2025-09-08)


### Bug Fixes

* change metadata-key-prefix to s3pe- and remove the encrypted flag entirely ([403fc7b](https://github.com/guided-traffic/s3-encryption-proxy/commit/403fc7bf2a5c50e4739b3c24b5b94bf42b3f61f1))
* comment in factory ([a7c6cf9](https://github.com/guided-traffic/s3-encryption-proxy/commit/a7c6cf96b1f5509bc7c9586cadd7ee74f5a1e066))
* gosec ([386ce89](https://github.com/guided-traffic/s3-encryption-proxy/commit/386ce89e291d37f9c72e1731f0e0fe34bdbbf610))
* tests ([d4a4cfa](https://github.com/guided-traffic/s3-encryption-proxy/commit/d4a4cfab73ecc6a66edfbeeff20b2680e77bd429))


### Features

* refactor folder structure ([1eb4b56](https://github.com/guided-traffic/s3-encryption-proxy/commit/1eb4b56860012e46e844130db89c1fbfb1ed23aa))
* rename RSA provider ([90608de](https://github.com/guided-traffic/s3-encryption-proxy/commit/90608de69eef08591baeb70fe328b61d52c57717))
* separate AES KEK and DEK processing ([4a3f434](https://github.com/guided-traffic/s3-encryption-proxy/commit/4a3f4340cce8967ea1475f58ac06f6af0ddaf210))
* support kek fingerprints ([c175a62](https://github.com/guided-traffic/s3-encryption-proxy/commit/c175a6249dcee37dcea7f9d1560b35506291f043))

## [1.15.2](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.15.1...v1.15.2) (2025-09-07)


### Bug Fixes

* **deps:** Lock file maintenance ([2ecadc6](https://github.com/guided-traffic/s3-encryption-proxy/commit/2ecadc6e5dad1bbb00cd51899607ae1dfbbb1dda))

## [1.15.1](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.15.0...v1.15.1) (2025-09-07)


### Bug Fixes

* **deps:** Update actions/setup-node action to v5 ([e43c4bc](https://github.com/guided-traffic/s3-encryption-proxy/commit/e43c4bcd24dc1ce51d4adc2b8d63ddceea1b3dfe))

# [1.15.0](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.14.1...v1.15.0) (2025-09-07)


### Bug Fixes

* add integration for chunks ([9085da6](https://github.com/guided-traffic/s3-encryption-proxy/commit/9085da6fd35ff0a273d809f459743222f7c56772))
* add ssl-setup for minio ([707ad53](https://github.com/guided-traffic/s3-encryption-proxy/commit/707ad53cc4febe1642948e4ff70a3a8547c4e80e))
* all integration tests ([d401200](https://github.com/guided-traffic/s3-encryption-proxy/commit/d401200f0b40dffe5f2ef6510c022d6815e60b67))
* CI-pipeline ([468f65f](https://github.com/guided-traffic/s3-encryption-proxy/commit/468f65fd4e0c014e031ade06d3516f7ec7b03ba3))
* ci-pipeline gosec ([54edfca](https://github.com/guided-traffic/s3-encryption-proxy/commit/54edfca22c4b5ee68f6c34260ee303763751be38))
* demo setup ([6d8e804](https://github.com/guided-traffic/s3-encryption-proxy/commit/6d8e80418106e3e44373fe817fc201899bf59fd5))
* health endpoint logging configurable ([a64be81](https://github.com/guided-traffic/s3-encryption-proxy/commit/a64be81e2012823d488bc2d03ab30448b8a15915))
* integration test ([6e505f7](https://github.com/guided-traffic/s3-encryption-proxy/commit/6e505f7ecd63ce8dc8064c13a0abcd8d9c0bdc4d))
* remove caching from ci entirely ([1275e3c](https://github.com/guided-traffic/s3-encryption-proxy/commit/1275e3c88910306f5cf29204d3adfbbe4359ef3b))
* remove caching from ci-pipeline ([03853a9](https://github.com/guided-traffic/s3-encryption-proxy/commit/03853a96521c8a6e8c2d84334717585b3de39004))
* streaming encryption ([5830a85](https://github.com/guided-traffic/s3-encryption-proxy/commit/5830a8582b546060be687ed14e70d49c45cd94c1))
* test file ([05623c3](https://github.com/guided-traffic/s3-encryption-proxy/commit/05623c3a6f3da3d2e1f8b10ccc58854d0d25bc82))
* testing ([3e791a7](https://github.com/guided-traffic/s3-encryption-proxy/commit/3e791a7ba1a8cf2ae997689d6573689ebe824fcc))
* unit-tests ([400d060](https://github.com/guided-traffic/s3-encryption-proxy/commit/400d060368f18b791a1d0f637b5b975e45dd8e85))
* update integration-test workflow ([6726d07](https://github.com/guided-traffic/s3-encryption-proxy/commit/6726d070b4c585687b51ecdff90bb13966373635))
* whitespace ([d69ebfa](https://github.com/guided-traffic/s3-encryption-proxy/commit/d69ebfaaf0448af4ece4334c729c1518f39bdffd))
* wip ([c16ab13](https://github.com/guided-traffic/s3-encryption-proxy/commit/c16ab136f93552f69c3e9c1bc3fe0245fadbc414))


### Features

* add new failing tests ([67b8128](https://github.com/guided-traffic/s3-encryption-proxy/commit/67b81283bf397febfe98f5a24f4902dee376ea24))
* impl chunked reader ([fa1766a](https://github.com/guided-traffic/s3-encryption-proxy/commit/fa1766aa1b59c5682afb0d78c0dd217272b8422d))
* streaming encryption is now working again ([8bd79b6](https://github.com/guided-traffic/s3-encryption-proxy/commit/8bd79b6c0a94b0840e921e07c263c23ca914c34c))
* streaming encryption repaired ([f3f8876](https://github.com/guided-traffic/s3-encryption-proxy/commit/f3f8876537e3aca9e70b2c20ec428eeaad6259e0))
* streaming uploads everywhere ([f4ee61a](https://github.com/guided-traffic/s3-encryption-proxy/commit/f4ee61a58009899b08ce6470f9827a7d52dba929))
* switch to AES streaming ([67ae613](https://github.com/guided-traffic/s3-encryption-proxy/commit/67ae61360a53efb99f5dcafdcd822217d2216094))
* update streaming multipart uploads ([a7149f8](https://github.com/guided-traffic/s3-encryption-proxy/commit/a7149f84f78fa58e69fa219ad92283fa8a263f40))

## [1.14.1](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.14.0...v1.14.1) (2025-09-04)


### Bug Fixes

* integration tests ([f8b42b9](https://github.com/guided-traffic/s3-encryption-proxy/commit/f8b42b918bf19f897600b16e464616da3fe99f6d))

# [1.14.0](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.13.2...v1.14.0) (2025-09-04)


### Bug Fixes

* all tests ([5ae66ad](https://github.com/guided-traffic/s3-encryption-proxy/commit/5ae66ad64ba7920f2db7c38947777d5b95f3cea7))
* compare data with assert instead of bytes ([7ef02d3](https://github.com/guided-traffic/s3-encryption-proxy/commit/7ef02d3c6d4cd69951a0cd415dbdd5efb22580b1))
* **deps:** Update actions/setup-go action to v6 ([a9099f8](https://github.com/guided-traffic/s3-encryption-proxy/commit/a9099f8f82e791e5438d270a120a9f762f848d2d))
* integration tests ([a0ad8ad](https://github.com/guided-traffic/s3-encryption-proxy/commit/a0ad8ad63b5202303139f631d4590302525a9a05))
* linting issues ([b32c063](https://github.com/guided-traffic/s3-encryption-proxy/commit/b32c063614a5823921a384427981d6fefc64d31d))
* routing for ListObjectsV2 ([90569e6](https://github.com/guided-traffic/s3-encryption-proxy/commit/90569e649cf1e12c789fa04ce4ebba784023b053))
* tests ([f9fbb8c](https://github.com/guided-traffic/s3-encryption-proxy/commit/f9fbb8c887453c2a734336fbee3f2a3888d883fc))


### Features

* new multipart upload capabilities ([9d88a28](https://github.com/guided-traffic/s3-encryption-proxy/commit/9d88a28cdd9209a5342cb81b5fa5303ae021fcd4))

## [1.13.2](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.13.1...v1.13.2) (2025-09-04)


### Bug Fixes

* better logging for notImplemented S3 Functions ([ffe5e0e](https://github.com/guided-traffic/s3-encryption-proxy/commit/ffe5e0e084d04ded14a1d1365b3456674ff59a4e))

## [1.13.1](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.13.0...v1.13.1) (2025-09-04)


### Bug Fixes

* add bucket_logging integration test ([776909c](https://github.com/guided-traffic/s3-encryption-proxy/commit/776909c1c4f4bf165ba2995a55ee225c1cb40a41))

# [1.13.0](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.12.0...v1.13.0) (2025-09-04)


### Features

* impl handleBucketLogging ([1cd3d72](https://github.com/guided-traffic/s3-encryption-proxy/commit/1cd3d722d3a9ae62a18445cf80f9a4b2acd6b387))

# [1.12.0](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.11.1...v1.12.0) (2025-09-04)


### Features

* impl handleBucketLocation ([83fc9ed](https://github.com/guided-traffic/s3-encryption-proxy/commit/83fc9ed2202b8f85144a5fb7e2be1326278cfdc1))

## [1.11.1](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.11.0...v1.11.1) (2025-09-04)


### Bug Fixes

* remove some whitespaces ([068224e](https://github.com/guided-traffic/s3-encryption-proxy/commit/068224eb95693e258bb88dbd450c8154d24bd919))

# [1.11.0](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.10.0...v1.11.0) (2025-09-04)


### Features

* impl handleBucketPolicy ([ab98d81](https://github.com/guided-traffic/s3-encryption-proxy/commit/ab98d81c4d336c67e228be0ce55ee55f1eecc4e2))

# [1.10.0](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.9.4...v1.10.0) (2025-09-03)


### Bug Fixes

* ci-workflow ([6a6d8a2](https://github.com/guided-traffic/s3-encryption-proxy/commit/6a6d8a2150d3001cfcf0be20b5a45cc5df4c77cc))
* **deps:** Update golang Docker tag to v1.25 ([baa5533](https://github.com/guided-traffic/s3-encryption-proxy/commit/baa553306e9c8271b771a741b0eb1e3e146c6d29))
* linter issues ([715f3cb](https://github.com/guided-traffic/s3-encryption-proxy/commit/715f3cbebef708612b27645a5a5a468488509a49))
* SBOM upload ([0b129d4](https://github.com/guided-traffic/s3-encryption-proxy/commit/0b129d4ffc677e7ae778fcf941a59ef2a228acfb))
* testing ([96f0414](https://github.com/guided-traffic/s3-encryption-proxy/commit/96f04142d5351b539b3642d5ccd8e18349363ee1))
* testing ([4cf8065](https://github.com/guided-traffic/s3-encryption-proxy/commit/4cf8065d8239e342c15e2043b62a4e83c20d839c))
* tests ([ade0f71](https://github.com/guided-traffic/s3-encryption-proxy/commit/ade0f711c55e63119d62909f4639c993602ba391))


### Features

* impl  handleBucketACL ([ca5f9bd](https://github.com/guided-traffic/s3-encryption-proxy/commit/ca5f9bd8bbf22781c7609fc7bba0b63e75f00759))
* impl handleBucketCORS ([22be442](https://github.com/guided-traffic/s3-encryption-proxy/commit/22be442ba3700a6362ec361ec1e4cffe73e0bc99))

## [1.9.4](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.9.3...v1.9.4) (2025-09-03)


### Bug Fixes

* update co-polot behavior ([2ed82cb](https://github.com/guided-traffic/s3-encryption-proxy/commit/2ed82cbd3000e5e09db65697d57043cdf4db40b8))

## [1.9.3](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.9.2...v1.9.3) (2025-09-03)


### Bug Fixes

* disable github cache while building images ([47e9222](https://github.com/guided-traffic/s3-encryption-proxy/commit/47e9222844b59d6125b5a444190378535c032ee8))

## [1.9.2](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.9.1...v1.9.2) (2025-09-03)


### Bug Fixes

* docker build caching ([71e3b04](https://github.com/guided-traffic/s3-encryption-proxy/commit/71e3b040a386cf752660e8ad2310e70aabb5adbe))

## [1.9.1](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.9.0...v1.9.1) (2025-09-03)


### Bug Fixes

* image tag versions add a v before ([9d87621](https://github.com/guided-traffic/s3-encryption-proxy/commit/9d87621faa9027c52946768203555f340b54e79e))

# [1.9.0](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.8.1...v1.9.0) (2025-09-03)


### Features

* add container security ([8d5d44c](https://github.com/guided-traffic/s3-encryption-proxy/commit/8d5d44c12e7f7038f3cc9d512760c2a79922cc4d))

## [1.8.1](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.8.0...v1.8.1) (2025-09-02)


### Bug Fixes

* **deps:** Lock file maintenance ([3be758f](https://github.com/guided-traffic/s3-encryption-proxy/commit/3be758fdd282345a7fa9c338a63b713f7185ca94))

# [1.8.0](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.7.1...v1.8.0) (2025-09-02)


### Bug Fixes

* liniting & tests ([2716c23](https://github.com/guided-traffic/s3-encryption-proxy/commit/2716c235c09739725ce8ead3d9614554b3e2b3fa))


### Features

* add BucketSubResource Impl ([6a11197](https://github.com/guided-traffic/s3-encryption-proxy/commit/6a11197090727940536fcf21e180224c851cc715))

## [1.7.1](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.7.0...v1.7.1) (2025-09-02)


### Bug Fixes

* **deps:** Update aws-sdk-go-v2 monorepo ([1ad3935](https://github.com/guided-traffic/s3-encryption-proxy/commit/1ad3935f2a7bbfbd21f0662dd6cae3589074343a))
* security issue ([2281828](https://github.com/guided-traffic/s3-encryption-proxy/commit/2281828094d601de2b9a03d9cbdd913f51e9bc56))
* security issue ([a2aabec](https://github.com/guided-traffic/s3-encryption-proxy/commit/a2aabec5042dc6b26427ae1882d8dd6ea83bf4ca))
* security issue ([0db7142](https://github.com/guided-traffic/s3-encryption-proxy/commit/0db714228e918630a8803bd5a3263225281ee6f5))
* update tests ([f7fb6b8](https://github.com/guided-traffic/s3-encryption-proxy/commit/f7fb6b81ff44783024d5f7686086424afbe776b6))

# [1.7.0](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.6.0...v1.7.0) (2025-09-02)


### Bug Fixes

* security issue ([ac873f8](https://github.com/guided-traffic/s3-encryption-proxy/commit/ac873f85c2b782efb2dfdeabe7bd936e2e89db8a))
* security issue ([70c3193](https://github.com/guided-traffic/s3-encryption-proxy/commit/70c31930dd4ba8232599f07dfb10ee036b2f6ec1))
* security issue ([3a63c5a](https://github.com/guided-traffic/s3-encryption-proxy/commit/3a63c5a90ffb1458ff79e354c3a1e6591f885cbf))
* update tests ([5423323](https://github.com/guided-traffic/s3-encryption-proxy/commit/542332325f9310451a64e9c4385c45e6211e343b))


### Features

* add demo setup as compose and upgrade deps to aws-sdk-go-v2 ([b5751d5](https://github.com/guided-traffic/s3-encryption-proxy/commit/b5751d587829b14f71d672b6265e1d9c51a6c1f5))

# [1.6.0](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.5.5...v1.6.0) (2025-09-02)


### Bug Fixes

* wrong check to make security checks pass ([e778fba](https://github.com/guided-traffic/s3-encryption-proxy/commit/e778fba1c98c343a16b7d358c4bedc579ac8d2bd))


### Features

* release RSA envelop encryption ([a0cc402](https://github.com/guided-traffic/s3-encryption-proxy/commit/a0cc402001547df84dd0d30e7a6a8933c77d8e31))

## [1.5.5](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.5.4...v1.5.5) (2025-09-02)


### Bug Fixes

* **deps:** Update semantic-release monorepo ([d131221](https://github.com/guided-traffic/s3-encryption-proxy/commit/d1312219db191fc79c0a5f2018ff8a9994b87279))
* **deps:** Update softprops/action-gh-release action to v2 ([a251cad](https://github.com/guided-traffic/s3-encryption-proxy/commit/a251cadcfb4a7259a20fd4af89dc512fdddbcffa))
* remove old monolytic encrptyion mehtode ([be22965](https://github.com/guided-traffic/s3-encryption-proxy/commit/be229653c470dedd93c242924a90336ded809129))

## [1.5.4](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.5.3...v1.5.4) (2025-09-02)


### Bug Fixes

* **deps:** Update docker/build-push-action action to v6 ([cd4cfea](https://github.com/guided-traffic/s3-encryption-proxy/commit/cd4cfea2cf9c4ecc6f6656f53cd03d5855efc3be))
* **deps:** Update renovatebot/github-action action to v43 ([01a1630](https://github.com/guided-traffic/s3-encryption-proxy/commit/01a163005c5c12315aee9d3ee06c0e565f6b8f14))

## [1.5.3](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.5.2...v1.5.3) (2025-09-02)


### Bug Fixes

* **deps:** Update actions/download-artifact action to v5 ([0a76dbb](https://github.com/guided-traffic/s3-encryption-proxy/commit/0a76dbbccb0e2fda92c9398f51c6772ecade3662))
* **deps:** Update azure/setup-helm action to v4 ([f12d072](https://github.com/guided-traffic/s3-encryption-proxy/commit/f12d0724bd969ee73d1da6c1fbe81fd3171fa3da))

## [1.5.2](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.5.1...v1.5.2) (2025-09-02)


### Bug Fixes

* renovate pipeline ([8d02eb4](https://github.com/guided-traffic/s3-encryption-proxy/commit/8d02eb4c6080aa4909952c0438337a0d78d5e1cd))

## [1.5.1](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.5.0...v1.5.1) (2025-09-02)


### Bug Fixes

* **deps:** Update golang Docker tag to v1.25 ([4ef458e](https://github.com/guided-traffic/s3-encryption-proxy/commit/4ef458e8bdde784226aaf7dda1283d22c9680e50))

# [1.5.0](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.4.8...v1.5.0) (2025-09-02)


### Bug Fixes

* **deps:** Update dependency go to v1.25.0 ([abb1bb1](https://github.com/guided-traffic/s3-encryption-proxy/commit/abb1bb1b4db64123432a81f330743a6637b461e3))
* **deps:** Update module github.com/aws/aws-sdk-go to v1.55.8 ([c184091](https://github.com/guided-traffic/s3-encryption-proxy/commit/c1840913d6cc847b3120a8049da9ed6899c58092))
* **deps:** Update module github.com/spf13/cobra to v1.10.1 ([c8bb2d5](https://github.com/guided-traffic/s3-encryption-proxy/commit/c8bb2d5b51f2117c9c4875a273037eb015f8a0ad))


### Features

* upgrade to go 1.25.0 ([2240cbf](https://github.com/guided-traffic/s3-encryption-proxy/commit/2240cbfdc040184b1c2e8f67f8ffc9cd91175036))

## [1.4.8](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.4.7...v1.4.8) (2025-09-02)


### Bug Fixes

* dependency issues ([7e8a402](https://github.com/guided-traffic/s3-encryption-proxy/commit/7e8a4024ab6e89c20d40b3b9ae49a2c65eefdadd))
* **deps:** Update actions/checkout action to v5 ([950db81](https://github.com/guided-traffic/s3-encryption-proxy/commit/950db817b256edbeb78e7111c81082433256d221))
* **deps:** Update module github.com/aws/aws-sdk-go to v1.55.8 ([2334eab](https://github.com/guided-traffic/s3-encryption-proxy/commit/2334eabf037e25564b6eb2dd30bd53945afe98f1))
* **deps:** Update module github.com/spf13/viper to v1.20.1 ([2b59921](https://github.com/guided-traffic/s3-encryption-proxy/commit/2b59921972f47e1fd0861fefe701a66eddefae17))
* **deps:** Update renovatebot/github-action action to v40.3.6 ([a0a33c1](https://github.com/guided-traffic/s3-encryption-proxy/commit/a0a33c1df55cc4954801e246df94e887cef9f12d))

## [1.4.7](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.4.6...v1.4.7) (2025-09-02)


### Bug Fixes

* **deps:** Update module github.com/aws/aws-sdk-go to v1.55.8 ([8245053](https://github.com/guided-traffic/s3-encryption-proxy/commit/824505368662cf43339f2a2fb392fd3b9ef38b0d))

## [1.4.6](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.4.5...v1.4.6) (2025-09-02)


### Bug Fixes

* **deps:** Update actions/checkout action to v5 ([b569ad6](https://github.com/guided-traffic/s3-encryption-proxy/commit/b569ad663e925ceab4aa773fe406eb0c40e4d6e6))
* **deps:** Update renovatebot/github-action action to v40.3.6 ([b79cb3e](https://github.com/guided-traffic/s3-encryption-proxy/commit/b79cb3e450eac0a7006cd4913b9c898f9e15ea19))

## [1.4.5](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.4.4...v1.4.5) (2025-09-02)


### Bug Fixes

* **deps:** Update module github.com/spf13/cobra to v1.10.1 ([5958061](https://github.com/guided-traffic/s3-encryption-proxy/commit/59580619298c8ad7c4ecb95907ccefba2c8f1fc2))

## [1.4.4](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.4.3...v1.4.4) (2025-09-02)


### Bug Fixes

* **deps:** Update module github.com/stretchr/testify to v1.11.1 ([b8f3df3](https://github.com/guided-traffic/s3-encryption-proxy/commit/b8f3df3085891e93d00f81bd2a6f0d7e40d6171e))

## [1.4.3](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.4.2...v1.4.3) (2025-09-02)


### Bug Fixes

* **deps:** Update module github.com/gorilla/mux to v1.8.1 ([9de1243](https://github.com/guided-traffic/s3-encryption-proxy/commit/9de124383cc94a36edb66f78083780ac4027f5e0))
* pipeline ([068ecd9](https://github.com/guided-traffic/s3-encryption-proxy/commit/068ecd9658395a08ea456c12f7b1b0abd2d7a174))

## [1.4.2](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.4.1...v1.4.2) (2025-09-01)


### Bug Fixes

* **deps:** migrate config renovate.json ([1a26117](https://github.com/guided-traffic/s3-encryption-proxy/commit/1a26117f1d01f9ec185fa2e2875c5d66d9ff984c))
* integration tests ([3f2213a](https://github.com/guided-traffic/s3-encryption-proxy/commit/3f2213aef3b3f1856f8d65577061920f83a5b867))

## [1.4.1](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.4.0...v1.4.1) (2025-09-01)


### Bug Fixes

* integration tests ([c19093f](https://github.com/guided-traffic/s3-encryption-proxy/commit/c19093f3559c907308add2e03955e10f7645196f))


# [1.4.0](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.3.2...v1.4.0) (2025-09-01)


### Bug Fixes

* renovate settings ([eca8210](https://github.com/guided-traffic/s3-encryption-proxy/commit/eca821049410b837ecabf2fc670ba7efe1af4ce1))


### Features

* add integration testing ([4e2ae51](https://github.com/guided-traffic/s3-encryption-proxy/commit/4e2ae5191f7833218207c106e657f35a121ad78f))

## [1.3.2](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.3.1...v1.3.2) (2025-09-01)


### Bug Fixes

* renovate ([4d8022f](https://github.com/guided-traffic/s3-encryption-proxy/commit/4d8022f4ab874834726b44a49fee7f301703936a))

## [1.3.1](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.3.0...v1.3.1) (2025-09-01)


### Bug Fixes

* let renovate run on self-hosted infrastrukture ([85daa18](https://github.com/guided-traffic/s3-encryption-proxy/commit/85daa1846d519b952ccf0246b5541c295f9c0df8))

# [1.3.0](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.2.4...v1.3.0) (2025-09-01)


### Features

* install renovate ([9d31251](https://github.com/guided-traffic/s3-encryption-proxy/commit/9d312513e7a48e0b075893361c1434a8d21f212d))

## [1.2.4](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.2.3...v1.2.4) (2025-09-01)


### Bug Fixes

* switch to go 1.24 for testing ([23a10a6](https://github.com/guided-traffic/s3-encryption-proxy/commit/23a10a689772345348a11072939deba1290539e2))
* upgrade go packages ([17be5b1](https://github.com/guided-traffic/s3-encryption-proxy/commit/17be5b1921479951bbd07ce27b07515d2722892e))

## [1.2.3](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.2.2...v1.2.3) (2025-09-01)


### Bug Fixes

* update release workflow ([7c30a92](https://github.com/guided-traffic/s3-encryption-proxy/commit/7c30a92e31f8c594dd03c7d1ad9ff46d63b16f79))

## [1.2.2](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.2.1...v1.2.2) (2025-09-01)


### Bug Fixes

* gitignore issue ([1d831f4](https://github.com/guided-traffic/s3-encryption-proxy/commit/1d831f49a64fe92cdaec3a8a1f6e186299b8e6b4))

## [1.2.1](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.2.0...v1.2.1) (2025-09-01)


### Bug Fixes

* add helm release ([fb8a7e4](https://github.com/guided-traffic/s3-encryption-proxy/commit/fb8a7e4f07a44105bb4474f0f7e827f5f1f3e9f7))
* add some tests ([60a291c](https://github.com/guided-traffic/s3-encryption-proxy/commit/60a291c882bda888dcd16d4e4be02b56a2c57f1e))
* build process ([64181d0](https://github.com/guided-traffic/s3-encryption-proxy/commit/64181d0c3c39dbe52bd9608eea23b853dfdd0bb0))
* tests ([e3dbbb6](https://github.com/guided-traffic/s3-encryption-proxy/commit/e3dbbb6cfbc77662b4d57cf30f696c0b6be8ac03))

# [1.2.0](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.1.0...v1.2.0) (2025-08-31)


### Bug Fixes

* downgrade Go version requirement to 1.23 for CI compatibility ([f0cbcd0](https://github.com/guided-traffic/s3-encryption-proxy/commit/f0cbcd0397ac38a0e8eeb22466a6f20b35c651d0))
* enhance test coverage ([4d1c2cb](https://github.com/guided-traffic/s3-encryption-proxy/commit/4d1c2cb660839e0e13ba10729193681a2bebffe8))
* enhance test coverage ([7e5a411](https://github.com/guided-traffic/s3-encryption-proxy/commit/7e5a41124d9a3e0fe7695e6118115d0d0005624c))
* resolve CI pipeline test and security issues ([1142490](https://github.com/guided-traffic/s3-encryption-proxy/commit/11424908307b74fdd3c5d78a2356a7cb0db26bb5))


### Features

* added helm chart ([e891729](https://github.com/guided-traffic/s3-encryption-proxy/commit/e8917291b591ec986713aa0a2c3b058a1fcdc669))

# [1.1.0](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.0.4...v1.1.0) (2025-08-31)


### Bug Fixes

* better config ([353dae6](https://github.com/guided-traffic/s3-encryption-proxy/commit/353dae6d1e89c06528d4b28f6be6879c743336be))
* liniting and test problems ([424dca4](https://github.com/guided-traffic/s3-encryption-proxy/commit/424dca4b8cb28680df7207b8208c8c812f855a2f))
* organise encryption methods ([0e59604](https://github.com/guided-traffic/s3-encryption-proxy/commit/0e59604e4c64c8d545a0efe53c40e5c7eefa4a2f))


### Features

* add s3 pass through encryption logic and none-type encryption ([6c37fff](https://github.com/guided-traffic/s3-encryption-proxy/commit/6c37fff34084ab3f4e5b489025ec7b3dd619af88))
* add tls support ([efed840](https://github.com/guided-traffic/s3-encryption-proxy/commit/efed840709f2f14e2f440272bf5a3bcbcdbba193))

## [1.0.4](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.0.3...v1.0.4) (2025-08-31)


### Bug Fixes

* working on release process ([2ac5dd8](https://github.com/guided-traffic/s3-encryption-proxy/commit/2ac5dd865e72424047caa27e2a7c72552babd986))

## [1.0.3](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.0.2...v1.0.3) (2025-08-31)


### Bug Fixes

* working on release process ([9d76145](https://github.com/guided-traffic/s3-encryption-proxy/commit/9d7614576aaf66827c804427838f5da31b26615c))
* working on release process ([879ed9e](https://github.com/guided-traffic/s3-encryption-proxy/commit/879ed9e5d74af3e76deaff74b3688b34b1440123))

## [1.0.2](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.0.1...v1.0.2) (2025-08-30)


### Bug Fixes

* improve release process ([cc1b502](https://github.com/guided-traffic/s3-encryption-proxy/commit/cc1b50206e8edc8689d0e5e57498a2c79763692e))

## [1.0.1](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.0.0...v1.0.1) (2025-08-30)


### Bug Fixes

* improve release process ([ecaa3b0](https://github.com/guided-traffic/s3-encryption-proxy/commit/ecaa3b0ab1b12269d1f9bff89d0155c8081a7738))

# 1.0.0 (2025-08-30)


### Bug Fixes

* add LICENSE ([da7ed81](https://github.com/guided-traffic/s3-encryption-proxy/commit/da7ed81b0a4067ebd8d09a8f58fb576bc099818f))
* gh test workflow ([29da299](https://github.com/guided-traffic/s3-encryption-proxy/commit/29da2997ae17311f17d5c073b0f295d3a492ceba))
* gosec issues ([efaa577](https://github.com/guided-traffic/s3-encryption-proxy/commit/efaa577c62fb1934d6ecfd44dfe8949587283974))
* linter issues ([92f552a](https://github.com/guided-traffic/s3-encryption-proxy/commit/92f552ab3382b972b9ff3f281dbb197857cc5e88))
* release pipeline ([bbfeb60](https://github.com/guided-traffic/s3-encryption-proxy/commit/bbfeb60c42814e2756c004ffd78a2969df2cd7f0))
* release pipeline ([6308231](https://github.com/guided-traffic/s3-encryption-proxy/commit/6308231519cea4e8cbdaa43f1a913b0e4fe65418))
* security check ([3d80cd6](https://github.com/guided-traffic/s3-encryption-proxy/commit/3d80cd6e30819539de3d6b7df473e4f6862f5d59))
* security check ([7a34d5c](https://github.com/guided-traffic/s3-encryption-proxy/commit/7a34d5c6386dbc7af4540518aab843f4778750c5))
* security check ([f9a8786](https://github.com/guided-traffic/s3-encryption-proxy/commit/f9a87862176b2f956ad31cf531a28dca08a22082))
* security check ([d823447](https://github.com/guided-traffic/s3-encryption-proxy/commit/d823447ca785650d440705e525c6669d7196ed29))


### Features

* added AES256 file encryption ([4a04589](https://github.com/guided-traffic/s3-encryption-proxy/commit/4a04589f56fc8088e14770dc75c27ee412826595))
* create release process ([fbcacf3](https://github.com/guided-traffic/s3-encryption-proxy/commit/fbcacf3ea8dd2511725d011b78a397e31a4abd28))
* implementation starting point ([3dfcb87](https://github.com/guided-traffic/s3-encryption-proxy/commit/3dfcb87fec31653334fee0ad7de07da180763245))
* update configuration ([da86785](https://github.com/guided-traffic/s3-encryption-proxy/commit/da86785117dbf018342dd8150d592a74373f2a91))
* update to go 1.24.6 because 1.25.0 is not supported by different linters and vuln tools ([2ed4a06](https://github.com/guided-traffic/s3-encryption-proxy/commit/2ed4a06815af833d997a6d9271a14e7610bd4cf1))

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial implementation of S3 encryption proxy
- Google Tink envelope encryption support
- AES-256-GCM direct encryption support
- Configurable encryption algorithms
- Comprehensive unit and integration tests
- Docker containerization
- CI/CD pipeline with security scanning
- Key generation utility
- Comprehensive documentation

### Security
- All cryptographic operations use industry-standard libraries
- Security scanning with gosec and govulncheck
- No secrets stored in repository
