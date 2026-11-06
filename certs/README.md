# Certificate provenance

Public manufacturer certificate material, fetched November 6, 2026 from Wedgie’s deployed bundle. Certificates are trust material issued by Infineon; the project MIT license does not claim ownership of these certificates.

- Manufacturer reference: https://www.infineon.com/design-resources/platforms/optiga-software-tools/optiga-tpm-and-trust-certificates
- Upstream verification reference: https://github.com/clawdbotatg/wedgie-dev/blob/main/src/serial/chipcheck.ts
- Mirror source for each file: `https://wedgie.dev/device/infineon/<name>.crt`

`rootC` and `root2` are pinned roots; `ca101`, `ca300`, `ca306` are pinned Trust M intermediates. Device certificates supplied over USB are never accepted as trust roots. The runtime makes no CA downloads. The test PKI is generated in a temporary directory and is not accepted by production.

SHA-256 fingerprints:

- `rootC.crt`: `CF:EB:02:FE:CD:55:AD:7A:73:C6:E1:D1:19:85:D4:C4:7D:EE:24:8A:B6:3D:CB:66:09:1A:24:89:66:04:43:C3`
- `root2.crt`: `EE:0C:82:75:55:C4:E9:01:20:37:DF:42:57:BB:8A:AA:26:08:4A:17:B1:3E:DE:41:CD:78:95:C8:D6:C1:11:90`
- `ca101.crt`: `AE:F5:64:5D:16:B6:0D:F6:B9:57:92:E5:7C:6B:A9:74:9E:81:13:AF:D1:B1:CE:02:CE:08:B3:85:6D:D2:82:65`
- `ca300.crt`: `E4:EA:96:24:5C:3D:28:34:FE:4E:1C:28:48:36:7E:BD:24:EC:89:97:E1:C0:C5:1E:4D:36:21:11:DC:1D:83:87`
- `ca306.crt`: `4C:1D:5B:89:C8:A6:1B:07:72:55:9B:17:3E:90:93:AF:8A:29:CF:6D:D5:42:11:65:69:BB:C2:E7:13:ED:9D:93`
