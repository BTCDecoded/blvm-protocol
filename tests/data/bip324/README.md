# BIP324 reference vectors

Verbatim copies from bitcoin/bips commit `a50c0ea32b104832d15b10a3d65bc77ee8df98da`,
directory `bip-0324`. BIP324 and these files are BSD-3-Clause.

| File | SHA-256 |
| --- | --- |
| `packet_encoding_test_vectors.csv` | `61704507945e2fa99e6c799fab888593eb7a2c3d2018f42ee4a3c3abe0684269` |
| `ellswift_decode_test_vectors.csv` | `a238a66b093bed3c571d5b57cb2bb1f69487788f0f872f7ea7501b5b98be20b0` |

`packet_encoding_test_vectors.csv` pins the ECDH shared secret, the HKDF key
schedule, the garbage terminators, the session id, and the ciphertext of the
packet sent after `in_idx` empty packets. Rows cross the 224-packet rekey
boundary. `ellswift_decode_test_vectors.csv` pins ElligatorSwift decoding.
