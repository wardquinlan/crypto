package crypto;

import java.util.Properties;
import java.util.ArrayList;
import java.util.Enumeration;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.io.OutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.File;
import java.security.MessageDigest;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import org.apache.commons.logging.LogFactory;
import org.apache.commons.logging.Log;

public class Crypto {
  // logger
  private static Log log = LogFactory.getFactory().getInstance(Crypto.class);

  // empty string
  public static final String EMPTY = "";

  // encryption suffix
  public static final String SUFFIX = ".X";

  // version
  public static final String VERSION = "1.20";

  // properties
  private Properties props = null;

  // constructor
  public Crypto(ArrayList argList) {
    loadProperties();
    parseArgs(argList);
  }

  // shows usage
  private void usage() {
    System.out.println("crypto encrypt -key k [-force] [-nopreserve] file ...");
    System.out.println("  encrypts file(s) with key k\n");
    System.out.println("crypto decrypt -key k [-force] [-nopreserve] [-view] file ...");
    System.out.println("  decrypts file(s) with key k\n");
    System.out.println("crypto digest file ...");
    System.out.println("  computes message digest of file(s)\n");
    System.out.println("crypto digestkey -key k");
    System.out.println("  computes message digest of key k\n");
    System.out.println("crypto crypt -key k -salt s");
    System.out.println("  computes crypt of key k with salt s (requires perl)\n");
    System.out.println("crypto version");
    System.out.println("  shows version information\n");
    System.out.println("crypto help");
    System.out.println("  shows this screen\n");
  }

  // shows help screen
  private void doVersion() {
    System.out.println("crypto version " + VERSION);
    System.out.println("-------------------");
    Enumeration keys = props.keys();
    while(keys.hasMoreElements()) {
      String key = (String) keys.nextElement();
      String value = (String) props.get(key);
      System.out.println(key + "=" + value);
    }
    System.out.println(EMPTY);
  }

  // pad a key
  private String padKey(String key) {
    if (key.length() < 6) {
      log.error("key length too short");
      System.exit(1);
    }
    // get the keysize
    String keySizeStr = props.getProperty("crypto.cipher.keysize");
    if (keySizeStr == null) {
      log.error("panic: crypto.cipher.keysize not defined");
      System.exit(1);
    }
    int keySize = 0;
    try {
      if (Integer.parseInt(keySizeStr) % 8 != 0) {
        log.error("panic: crypto.cipher.keysize not divisible by 8");
        System.exit(1);
      }
      keySize = Integer.parseInt(keySizeStr) / 8;
    } catch(Exception e) {
      log.error("panic: crypto.cipher.keysize not an integer: " + keySizeStr);
      System.exit(1);
    }
    // append block of 0's to key
    StringBuffer buf = new StringBuffer(key);
    while (buf.length() < keySize) {
      buf.append('0');
    }
    return buf.substring(0, keySize).toString();
  }

  // encrypt or decrypt a file
  private void doCipher(String key, String file, int mode, boolean force, boolean nopreserve, boolean view) {
    File src = new File(file);
    File dest = null;
    if (mode == Cipher.ENCRYPT_MODE) {
      if (view) {
        log.warn(file + " ignored: -view used in ENCRYPT_MODE");
        return;
      }
      if (file.endsWith(SUFFIX)) {
        log.warn(file + " ends with '" + SUFFIX + "'; ignored");
        return;
      }
      dest = new File(file + SUFFIX);
    } else if (mode == Cipher.DECRYPT_MODE) {
      if (!file.endsWith(SUFFIX)) {
        log.warn(file + " does not end with '" + SUFFIX + "'; ignored");
        return;
      }
      if (view) {
        if (nopreserve) {
          log.warn(file + " ignored: -view used with -nopreserve");
          return;
        }
        if (force) {
          log.warn(file + " ignored: -view used with -force");
          return;
        }
      } else {
        StringBuffer sb = new StringBuffer(file);
        String tmp = sb.substring(0, file.length() - SUFFIX.length());
        dest = new File(tmp);
      }
    } else {
      log.error("panic: mode not defined: " + mode);
      System.exit(1);
    }
    if (dest != null && dest.exists() && !force) {
      log.warn(dest.getName() + " already exists; ignored");
      return;
    }
    String transformation = props.getProperty("crypto.cipher.transformation");
    if (transformation == null) {
      log.error("panic: crypto.cipher.transformation not defined");
      System.exit(1);
    }
    String algorithm = props.getProperty("crypto.cipher.algorithm");
    if (algorithm == null) {
      log.error("panic: crypto.cipher.algorithm not defined");
      System.exit(1);
    }
    IvParameterSpec ivSpec = null;
    String iv = props.getProperty("crypto.cipher.iv");
    if (iv != null && !iv.equals(EMPTY)) {
      ivSpec = new IvParameterSpec(iv.getBytes());
    }
    Cipher cipher = null;
    try {
      cipher = Cipher.getInstance(transformation);
      SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), algorithm);
      if (ivSpec == null) {
        cipher.init(mode, keySpec);
      } else {
        cipher.init(mode, keySpec, ivSpec);
      }
      byte[] srcBytes = new byte[(int) src.length()];
      FileInputStream fis = new FileInputStream(src);
      int bytesRead = fis.read(srcBytes);
      fis.close();
      if (bytesRead != srcBytes.length) {
        log.error("panic: unexpected # of bytes read: " + bytesRead);
        System.exit(1);
      }
      byte[] destBytes = cipher.doFinal(srcBytes);
      if (mode == Cipher.ENCRYPT_MODE) {
        FileOutputStream fos = new FileOutputStream(dest);
        fos.write(destBytes);
        fos.close();
      } else {
        if (dest == null) {
          System.out.write(destBytes);
        } else {
          FileOutputStream fos = new FileOutputStream(dest);
          fos.write(destBytes);
          fos.close();
        }
      }
      if (dest != null) {
        long bytesWritten = dest.length();
        if (bytesWritten != destBytes.length) {
          log.error("panic: unexpected # of bytes written: " + bytesWritten);
          System.exit(1);
        }
      }
      if (nopreserve) {
        try {
          shred(src, (byte) 0x00);
          shred(src, (byte) 0x55);
          shred(src, (byte) 0xaa);
          shred(src, (byte) 0xff);
        } catch(IOException e) {
          log.warn("could not shred: " + src.getName(), e);
        } finally {
          boolean f;
          if ("true".equals(props.getProperty("crypto.nodelete"))) {
            f = false;
          } else {
            f = src.delete();
          }
          if (!f) {
            log.warn("could not delete: " + src.getName());
          }
        }
      }
    } catch(Exception e) {
      log.warn("could not cipher: " + e.getMessage());
    }
  }

  // shred file with byte
  private void shred(File file, byte b) throws IOException {
    FileOutputStream fos = null;
    byte[] bytes = new byte[(int) file.length()];
    for (int i = 0; i < bytes.length; i++) {
      bytes[i] = b;
    }
    try {
      fos = new FileOutputStream(file);
      fos.write(bytes);
    } finally {
      if (fos != null) {
        try {
          fos.close();
        } catch(IOException e) {
          log.warn("could not close stream: " + file.getName(), e);
        }
      }
    }

    
  }

  // crypt key
  private void doCrypt(ArrayList argList) {
    String key = null;
    String salt = null;
    while (argList.size() != 0) {
      if (((String) argList.get(0)).equals("-key")) {
        if (argList.size() < 2) {
          usage();
          System.exit(1);
        }
        key = (String) argList.get(1);
        argList.remove(0);
        argList.remove(0);
      } else if (((String) argList.get(0)).equals("-salt")) {
        if (argList.size() < 2) {
          usage();
          System.exit(1);
        }
        salt = (String) argList.get(1);
        argList.remove(0);
        argList.remove(0);
      } else {
        usage();
        System.exit(1);
      }
    }
    if (key == null || salt == null) {
      usage();
      System.exit(1);
    }

    String cmd[] = new String[3];
    cmd[0] = "perl";
    cmd[1] = "-e";
    cmd[2] = "print crypt \"" + key + "\", \"" + salt + "\";";
    try {
      Process proc = Runtime.getRuntime().exec(cmd);
      InputStream in = proc.getInputStream();
      BufferedReader rdr = new BufferedReader(new InputStreamReader(in));
      while (true) {
        String text = rdr.readLine();
        if (text == null) {
          break;
        }
        System.out.println(text);
      } 
      int exitValue = proc.waitFor();
      if (exitValue != 0) {
        log.error("panic: child process ended abnormally: " + exitValue);
        System.exit(1);
      }
    } catch(Exception e) {
      log.error("panic: could not invoke perl", e);
      System.exit(1);
    }
  }

  // digest file
  private void doDigest(ArrayList argList) {
    String algorithm = props.getProperty("crypto.digest.algorithm");
    if (algorithm == null) {
      log.error("panic: crypto.digest.algorithm not defined");
      System.exit(1);
    }
    for (int i = 0; i < argList.size(); i++) {
      try {
        File src = new File((String) argList.get(i));
        byte[] srcBytes = new byte[(int) src.length()];
        FileInputStream fis = new FileInputStream(src);
        int bytesRead = fis.read(srcBytes);
        fis.close();
        if (bytesRead != srcBytes.length) {
          log.error("panic: unexpected # of bytes read: " + bytesRead);
          System.exit(1);
        }
        MessageDigest md = MessageDigest.getInstance(algorithm);
        byte[] bytes = md.digest(srcBytes);
        String digest = toHexString(bytes);
        System.out.println(src.getName() + ": " + digest);
      } catch(Exception e) {
        log.warn("could not digest: " + e.getMessage());
      }
    }
  }

  // converts a byte array to a hex string
  private String toHexString(byte[] bytes) {
    StringBuffer sb = new StringBuffer();
    for (int i = 0; i < bytes.length; i++) {
      String str = Integer.toHexString(bytes[i] & 0xff);
      if (str.length() == 1) {
        sb.append('0');
      }
      sb.append(str);
    }
    return sb.toString();
  }

  // digest key
  private void doDigestKey(ArrayList argList) {
    String key = null;
    if (argList.size() != 2) {
      usage();
      System.exit(1);
    }
    if (!((String) argList.get(0)).equals("-key")) {
      usage();
      System.exit(1);
    }
    key = (String) argList.get(1);

    String algorithm = props.getProperty("crypto.digest.algorithm");
    if (algorithm == null) {
      log.error("panic: crypto.digest.algorithm not defined");
      System.exit(1);
    }

    try {
      MessageDigest md = MessageDigest.getInstance(algorithm);
      byte[] bytes = md.digest(key.getBytes());
      String digest = toHexString(bytes);
      System.out.println(digest);
    } catch(Exception e) {
      log.warn("could not digest key: " + e.getMessage());
    }
  }

  // encrypt/decrypt operation
  private void doCipher(ArrayList argList, int mode) {
    String key = null;
    boolean force = false;
    boolean nopreserve = false;
    boolean view = false;

    while (argList.size() != 0) {
      if (((String) argList.get(0)).equals("-force")) {
        force = true;
        argList.remove(0);
      } else if (((String) argList.get(0)).equals("-nopreserve")) {
        nopreserve = true;
        argList.remove(0);
      } else if (((String) argList.get(0)).equals("-view")) {
        view = true;
        argList.remove(0);
      } else if (((String) argList.get(0)).equals("-key")) {
        if (argList.size() < 2) {
          usage();
          System.exit(1);
        }
        key = padKey((String) argList.get(1));
        argList.remove(0);
        argList.remove(0);
      } else {
        // end of arguments, beginning of files
        break;
      }
    }
    if (key == null) {
      usage();
      System.exit(1);
    }

    for (int i = 0; i < argList.size(); i++) {
      doCipher(key, (String) argList.get(i), mode, force, nopreserve, view);
    }
  }

  // parse the arguments and call the right operation
  private void parseArgs(ArrayList argList) {
    if (argList.size() == 0) {
      usage();
      System.exit(1);
    } else if ("version".equals((String) argList.get(0))) {
      argList.remove(0);
      doVersion();
    } else if ("encrypt".equals((String) argList.get(0))) {
      argList.remove(0);
      doCipher(argList, Cipher.ENCRYPT_MODE);
    } else if ("decrypt".equals((String) argList.get(0))) {
      argList.remove(0);
      doCipher(argList, Cipher.DECRYPT_MODE);
    } else if ("digest".equals((String) argList.get(0))) {
      argList.remove(0);
      doDigest(argList);
    } else if ("digestkey".equals((String) argList.get(0))) {
      argList.remove(0);
      doDigestKey(argList);
    } else if ("crypt".equals((String) argList.get(0))) {
      argList.remove(0);
      doCrypt(argList);
    } else if ("help".equals((String) argList.get(0))) {
      usage();
    } else {
      usage();
      System.exit(1);
    }
  }

  // loads properties
  private void loadProperties() {
    ClassLoader cl = ClassLoader.getSystemClassLoader();  
    props = new Properties();
    try {
      InputStream is = cl.getResourceAsStream("crypto.properties");
      if (is == null) {
        log.error("panic: cannot load properties");
        System.exit(1);
      }
      props.load(is);    
    } catch(IOException e) {
      log.error("panic: cannot load properties", e);
      System.exit(1);
    }
  }

  // main method
  public static void main(String args[]) {
    ArrayList argList = new ArrayList(args.length);
    for (int i = 0; i < args.length; i++) {
      argList.add(args[i]);
    }
    Crypto crypto = new Crypto(argList);
    System.exit(0);
  }
}
