# ec-keytool
A very simple piece of code to list or create ECDSA keys in a JCEKS keystore.

Note: you can specify a specific curve with keytool by setting `-keyalg EC` and `-keysize`. Sadly, it's
poorly documented and I figured that out after I wrote this code.

# building
mvn package

# example usage
```
$ java -cp ./bcprov-jdk15on.jar:./target/ec-keytool-1.0-SNAPSHOT.jar alokmenghrajani.EcKeytool genEcdsaKeyPair --alias p256 --curve secp256r1 --keystore test.jceks --storepass hushhush
$ java -cp ./bcprov-jdk15on.jar:./target/ec-keytool-1.0-SNAPSHOT.jar alokmenghrajani.EcKeytool genEcdsaKeyPair --alias p384 --curve secp384r1 --keystore test.jceks --storepass hushhush
$ java -cp ./bcprov-jdk15on.jar:./target/ec-keytool-1.0-SNAPSHOT.jar alokmenghrajani.EcKeytool genEcdsaKeyPair --alias p521 --curve secp521r1 --keystore test.jceks --storepass hushhush
$ java -cp ./bcprov-jdk15on.jar:./target/ec-keytool-1.0-SNAPSHOT.jar alokmenghrajani.EcKeytool list --keystore test.jceks --storepass hushhush                                          

Keystore type: jceks
Keystore provider: SunJCE

Your keystore contains 3 entries

Alias name: p384
Entry type: PrivateKeyEntry
  algorithm: EC
  params: secp384r1 [NIST P-384] (1.3.132.0.34)
  certificate signature: SHA256withECDSA

Alias name: p521
Entry type: PrivateKeyEntry
  algorithm: EC
  params: secp521r1 [NIST P-521] (1.3.132.0.35)
  certificate signature: SHA256withECDSA

Alias name: p256
Entry type: PrivateKeyEntry
  algorithm: EC
  params: secp256r1 [NIST P-256, X9.62 prime256v1] (1.2.840.10045.3.1.7)
  certificate signature: SHA256withECDSA
```
