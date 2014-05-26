package org.beangle.security.realm.ldap

import java.security.NoSuchAlgorithmException
import java.{ util => jl }
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import org.beangle.commons.codec.binary.Base64
import org.beangle.security.authc.BadCredentialsException
import javax.naming.directory.InitialDirContext
import javax.naming.Context
import org.beangle.commons.lang.Arrays
import org.beangle.commons.codec.binary.Hex

trait LdapPasswordValidator {

  def verify(name: String, password: String): Boolean
}

/**
 * @author chaostone
 */
class SimpleBindValidator(val userStore: LdapUserStore) extends LdapPasswordValidator {

  var properties = new jl.Hashtable[String, String]

  private def enviroment(userName: String, password: String): jl.Hashtable[String, String] = {
    val env = new jl.Hashtable[String, String]
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
    env.put(Context.PROVIDER_URL, userStore.url);
    env.put(Context.SECURITY_AUTHENTICATION, "simple");
    env.put(Context.SECURITY_PRINCIPAL, userName);
    env.put(Context.SECURITY_CREDENTIALS, password);
    env
  }

  override def verify(name: String, password: String): Boolean = {
    val env = enviroment(name, password)
    env.putAll(properties)
    try {
      new InitialDirContext(env).close()
      true
    } catch {
      case e: javax.naming.AuthenticationException => throw new BadCredentialsException(s"Bad credential $name", e)
      case e1: Exception => e1.printStackTrace(); false;
    }
  }
}

class DefaultLdapPasswordValidator(val userStore: LdapUserStore) extends LdapPasswordValidator {

  override def verify(name: String, password: String): Boolean = {
    val ldapPwd = userStore.getPassword(name)
    try {
      return (null != ldapPwd) && (LdapPasswordHandler.verify(ldapPwd, password))
    } catch {
      case e: NoSuchAlgorithmException => throw new RuntimeException(e)
    }
  }
}

object LdapPasswordHandler {

  def verify(digest: String, password: String): Boolean = {
    var alg: String = null;
    var size = 0;
    var digestContent = digest
    if (digest.regionMatches(true, 0, "{SHA}", 0, 5)) {
      digestContent = digest.substring(5);
      alg = "SHA-1";
      size = 20;
    } else if (digest.regionMatches(true, 0, "{SSHA}", 0, 6)) {
      digestContent = digest.substring(6);
      alg = "SHA-1";
      size = 20;
    } else if (digest.regionMatches(true, 0, "{MD5}", 0, 5)) {
      digestContent = digest.substring(5);
      alg = "MD5";
      size = 16;
    } else if (digest.regionMatches(true, 0, "{SMD5}", 0, 6)) {
      digestContent = digest.substring(6);
      alg = "MD5";
      size = 16;
    } else {
      return digestContent.equals(password);
    }

    val msgDigest = MessageDigest.getInstance(alg);
    val hs = split(Base64.decode(digestContent.toCharArray()), size)
    msgDigest.reset();
    msgDigest.update(password.getBytes());
    msgDigest.update(hs._2)
    MessageDigest.isEqual(hs._1, msgDigest.digest())
  }

  def generateDigest(password: String, saltHex: String, algorithm: String): String = {
    var alg = algorithm
    if (algorithm.equalsIgnoreCase("sha")) alg = "SHA-1";
    else if (algorithm.equalsIgnoreCase("md5")) alg = "MD5";
    val msgDigest = MessageDigest.getInstance(alg);
    val salt = if (saltHex == null) new Array[Byte](0) else Hex.decode(saltHex);
    var label: String = null;
    if (algorithm.startsWith("SHA")) label = if (salt.length <= 0) "{SHA}" else "{SSHA}";
    else if (algorithm.startsWith("MD5")) label = if (salt.length <= 0) "{MD5}" else "{SMD5}";
    msgDigest.reset();
    msgDigest.update(password.getBytes());
    msgDigest.update(salt);
    val pwhash = msgDigest.digest();
    val digest = new StringBuilder(if (null == label) "" else label)
    digest.append(Base64.encode(Arrays.concat(pwhash, salt)));
    digest.toString()
  }

  private def split(src: Array[Byte], n: Int): Tuple2[Array[Byte], Array[Byte]] = {
    var l: Array[Byte] = null
    var r: Array[Byte] = null
    if (src.length <= n) {
      l = src;
      r = new Array(0);
    } else {
      l = new Array[Byte](n)
      r = new Array[Byte](src.length - n)
      System.arraycopy(src, 0, l, 0, n);
      System.arraycopy(src, n, r, 0, r.length);
    }
    (l, r)
  }

}
