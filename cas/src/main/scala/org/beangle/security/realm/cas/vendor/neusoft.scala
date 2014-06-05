package org.beangle.security.realm.cas.vendor

import java.io.StringReader
import org.beangle.security.realm.cas.{ AbstractTicketValidator, Assertion, AssertionBean, TicketValidationException }
import org.xml.sax.{ Attributes, InputSource }
import org.xml.sax.XMLReader
import org.xml.sax.helpers.{ DefaultHandler, XMLReaderFactory }
import org.beangle.security.web.PreauthAliveChecker
import javax.servlet.http.HttpServletRequest
import org.beangle.security.session.Session
import org.beangle.commons.lang.Strings
import org.beangle.security.realm.cas.CasConfig
import org.beangle.security.authc.Account
import org.beangle.commons.web.util.HttpUtils

class NeusoftCasTicketValidator extends AbstractTicketValidator {
  encoding = "GBK"

  protected[vendor] override def parseResponse(ticket: String, response: String): Assertion = {
    val r = XMLReaderFactory.createXMLReader();
    r.setFeature("http://xml.org/sax/features/namespaces", false);
    val handler = new ServiceXmlHandler();
    r.setContentHandler(handler);
    r.parse(new InputSource(new StringReader(response)));
    handler.assertion
  }

  protected override final def populateUrlAttributeMap(urlParameters: collection.mutable.Map[String, String]) {
    urlParameters.put("checkAlive", "true")
  }
}

class ServiceXmlHandler extends DefaultHandler {

  protected var currentText = new StringBuffer()

  protected var authenticationSuccess = false;
  protected var netid: String = _
  private var userMap = new collection.mutable.HashMap[String, Object]
  protected var errorCode: String = _
  protected var errorMessage: String = _
  protected var pgtIou: String = _
  protected var user: String = _
  protected var proxyList = new collection.mutable.ListBuffer[String]
  protected var proxyFragment = false
  protected var checkAliveFragment = false
  protected var caKey: String = _

  override def startElement(ns: String, ln: String, qn: String, a: Attributes): Unit = {
    currentText = new StringBuffer();
    if (qn.equals("sso:authenticationSuccess")) authenticationSuccess = true;
    else if (qn.equals("sso:authenticationFailure")) {
      authenticationSuccess = false;
      errorCode = a.getValue("code");
      if (errorCode != null) errorCode = errorCode.trim();
    } else if (qn.equals("sso:attribute")) {
      userMap.put(a.getValue("name"), a.getValue("value"));
    }
    if (authenticationSuccess) {
      if (qn.equals("sso:proxies")) proxyFragment = true;
      if (qn.equals("sso:checkAliveTicket")) checkAliveFragment = true;
    }
  }

  override def characters(ch: Array[Char], start: Int, length: Int): Unit = {
    currentText.append(ch, start, length);
  }

  override def endElement(ns: String, ln: String, qn: String): Unit = {
    if (authenticationSuccess) {
      if (qn.equals("sso:user")) user = currentText.toString().trim();
      if (qn.equals("sso:proxyGrantingTicket")) pgtIou = currentText.toString().trim();
    } else if (qn.equals("sso:authenticationFailure")) errorMessage = currentText.toString().trim();
    if (qn.equals("sso:proxies")) proxyFragment = false;
    else if (proxyFragment && qn.equals("sso:proxy")) proxyList += currentText.toString().trim()
    if (qn.equals("sso:checkAliveTicket")) {
      checkAliveFragment = false;
      caKey = currentText.toString().trim();
    }
  }

  def assertion: Assertion = {
    if (authenticationSuccess) new AssertionBean(user, caKey, null, userMap.toMap)
    else throw new TicketValidationException(errorCode + ":" + errorMessage);
  }

}

/**
 * Check ticket alive
 */
class NeusoftCasAliveChecker extends PreauthAliveChecker{
  
  var config:CasConfig =_
  
   override def check(session: Session, request: HttpServletRequest): Boolean={
    session.principal match{
      case ac:Account => {
        ac.details.get("ticket") match{
          case Some(ticket) => Strings.contains(HttpUtils.getResponseText(Strings.concat(config.casServer,
            config.checkAliveUri, "?", config.artifactName , "=", ticket)),"true")
          case None => true
        }
      }
      case _ => true
    }
  }
} 