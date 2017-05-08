package alokmenghrajani;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;
import java.io.Console;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import org.apache.commons.io.FilenameUtils;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import static java.lang.String.format;

/**
 * A very simple piece of code to list or create ECDSA keys in a JCEKS keystore.
 *
 * Java's native keytool is sometimes a pain to use when dealing with elliptic curves. So I wrote
 * this little piece of code.  I tried to keep the command line arguments similat to the original
 * keytool.
  *
 * The goal of this code is however not to be as feature rich as keytool.
 */
public class EcKeytool {
  enum Curve {
    secp256r1,
    secp384r1,
    secp521r1
  }

  @Parameters(separators = "=", commandDescription = "Lists entries in a keystore with additional output for ECDSA keys")
  public static class ListCmd {
    @Parameter(names = "--keystore", description = "keystore name")
    public String keystore;

    @Parameter(names = "--storepass", description = "keystore password")
    public String storepass;

    @Parameter(names = "--storetype", description = "keystore type. If missing, guessed from keystore name")
    public String storetype;
  }

  @Parameters(separators = "=", commandDescription = "Generate ECDSA keys")
  public static class GenEcdsaKeyPairCmd {
    @Parameter(names = "--alias", description = "alias name of the entry to create")
    public String alias;

    @Parameter(names = "--curve", description = "curve to use")
    public Curve curve;

    @Parameter(names = "--keystore", description = "keystore name")
    public String keystore;

    @Parameter(names = "--storepass", description = "keystore password")
    public String storepass;

    @Parameter(names = "--storetype", description = "keystore type. If missing, guessed from keystore name")
    public String storetype;
  }

  @Parameter(names = "--help", help = true)
  private boolean help = false;

  public static void main(String[] argv) throws Exception {
    EcKeytool ecKeytool = new EcKeytool();
    ListCmd listCmd = new ListCmd();
    GenEcdsaKeyPairCmd genEcdsaKeyPairCmd = new GenEcdsaKeyPairCmd();
    JCommander jCommander = JCommander.newBuilder()
        .addObject(ecKeytool)
        .addCommand("list", listCmd)
        .addCommand("genEcdsaKeyPair", genEcdsaKeyPairCmd)
        .build();
    jCommander.setProgramName("EcKeytool");
    jCommander.parse(argv);
    if (ecKeytool.help) {
      jCommander.usage();
      return;
    }

    String command = jCommander.getParsedCommand();
    if (command == null) {
      jCommander.usage();
    } else if (command.equals("list")) {
      ecKeytool.list(listCmd);
    } else if (command.equals("genEcdsaKeyPair")) {
      ecKeytool.genEcdsaKeyPair(genEcdsaKeyPairCmd);
    }
  }

  public void list(ListCmd args) throws Exception {
    if (args.storetype == null) {
      // guess storetype using file extension
      args.storetype = FilenameUtils.getExtension(args.keystore);
    }
    KeyStore keyStore = KeyStore.getInstance(args.storetype);
    char[] pass;
    if (args.storepass != null) {
      pass = args.storepass.toCharArray();
    } else {
      pass = readPassword(args.keystore);
    }
    KeyStore.ProtectionParameter protParameter = new KeyStore.PasswordProtection(pass);
    keyStore.load(new FileInputStream(args.keystore), pass);

    System.out.println(format("\nKeystore type: %s\nKeystore provider: %s\n", keyStore.getType(),
        keyStore.getProvider().getName()));
    ArrayList<String> aliases = Collections.list(keyStore.aliases());

    if (aliases.size() == 1) {
      System.out.println("Your keystore contains 1 entry\n");
    } else {
      System.out.println(format("Your keystore contains %d entries", aliases.size()));
    }

    for (String alias : aliases) {
      KeyStore.Entry entry = keyStore.getEntry(alias, protParameter);
      System.out.println(format("\nAlias name: %s", alias));
      if (entry instanceof PrivateKeyEntry) {
        PrivateKeyEntry keyPair = (PrivateKeyEntry) entry;
        System.out.println("Entry type: PrivateKeyEntry");

        PublicKey publicKey = keyPair.getCertificate().getPublicKey();
        if (publicKey instanceof ECPublicKey) {
          ECPublicKey p = (ECPublicKey) publicKey;
          System.out.println(format("  algorithm: %s", p.getAlgorithm()));
          System.out.println(format("  params: %s", p.getParams()));
        } else {
          System.out.println(format("  unsupported public key type (%s)", publicKey.getClass()));
        }

        Certificate cert = keyPair.getCertificate();
        if (cert instanceof X509Certificate) {
          X509Certificate c = (X509Certificate) cert;
          System.out.println(format("  certificate signature: %s", c.getSigAlgName()));
        } else {
          System.out.println(format("  unsupported certificate type (%s)", cert.getClass()));
        }
      } else {
        System.out.println(format("  Entry type: %s", entry.getClass().getName()));
      }
    }
  }

  public void genEcdsaKeyPair(GenEcdsaKeyPairCmd args) throws Exception {
    if (args.storetype == null) {
      // guess storetype using file extension
      args.storetype = FilenameUtils.getExtension(args.keystore);
    }
    KeyStore keyStore = KeyStore.getInstance(args.storetype);
    char[] pass;
    if (args.storepass != null) {
      pass = args.storepass.toCharArray();
    } else {
      pass = readPassword(args.keystore);
    }
    KeyStore.ProtectionParameter protParameter = new KeyStore.PasswordProtection(pass);
    if (new File(args.keystore).exists()) {
      keyStore.load(new FileInputStream(args.keystore), pass);
    } else {
      keyStore.load(null, pass);
    }

    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
    kpg.initialize(new ECGenParameterSpec(args.curve.name()));
    KeyPair keyPair = kpg.generateKeyPair();
    X509Certificate cert = generateCertificate(keyPair);
    keyStore.setEntry(args.alias, new KeyStore.PrivateKeyEntry(keyPair.getPrivate(), new Certificate[] {cert}), protParameter);

    keyStore.store(new FileOutputStream(args.keystore), pass);
  }

  static X509Certificate generateCertificate(KeyPair keyPair) throws Exception {
    X509V3CertificateGenerator cert = new X509V3CertificateGenerator();
    cert.setSerialNumber(BigInteger.valueOf(new java.util.Random().nextInt() & 0x7fffffff));
    cert.setSubjectDN(new X509Principal("CN=EcKeyTool"));
    cert.setIssuerDN(new X509Principal("CN=EcKeyTool"));
    cert.setPublicKey(keyPair.getPublic());
    Date startDate = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
    Date expiryDate = new Date(System.currentTimeMillis() + 20 * 365 * 24 * 60 * 60 * 1000);
    cert.setNotBefore(startDate);
    cert.setNotAfter(expiryDate);
    cert.setSignatureAlgorithm("SHA256withECDSA");
    PrivateKey signingKey = keyPair.getPrivate();
    return cert.generate(signingKey);
  }

  public static char[] readPassword(String keystore) {
    Console console = System.console();
    if (console != null) {
      System.out.format("password for '%s': ", keystore);
      return console.readPassword();
    } else {
      throw new RuntimeException("when using pipes, please use --storepass to set password");
    }
  }
}
