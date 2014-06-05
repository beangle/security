package org.beangle.security.realm.cas

import java.io.StringReader
import java.net.{ MalformedURLException, URL, URLEncoder }
import java.util.Date
import org.beangle.commons.logging.Logging
import org.beangle.commons.web.util.HttpUtils
import org.xml.sax.{ Attributes, InputSource, XMLReader }
import org.xml.sax.helpers.{ DefaultHandler, XMLReaderFactory }
import javax.net.ssl.HostnameVerifier
import org.beangle.commons.lang.Strings
import java.io.BufferedReader

trait Assertion {

  def principal: String

  def ticket: String

  def validAt: Date
}

class AssertionBean(val principal: String, val ticket: String, val validAt: Date, val attributes: Map[String, Any]) extends Assertion

class TicketValidationException(message: String) extends Exception(message)

trait TicketValidator {

  /**
   * @throws TicketValidationException
   */
  def validate(ticket: String, service: String): Assertion
}

/**
 * Abstarct Ticket Validator
 */
abstract class AbstractTicketValidator extends TicketValidator with Logging {

  /** Hostname verifier used when making an SSL request to the CAS server. */
  var hostnameVerifier: HostnameVerifier = _

  var config: CasConfig = _

  var encoding: String = _

  /** A map containing custom parameters to pass to the validation url. */
  var customParameters: Map[String, String] = _

  /**
   * Template method for ticket validators that need to provide additional parameters to the
   * validation url.
   */
  protected def populateUrlAttributeMap(urlParameters: collection.mutable.Map[String, String]) {
    // nothing to do
  }

  /**
   * Constructs the URL to send the validation request to.
   */
  protected final def constructValidationUrl(ticket: String, serviceUrl: String): String = {
    val urlParameters = new collection.mutable.HashMap[String, String]
    urlParameters.put("ticket", ticket)
    urlParameters.put("service", encodeUrl(serviceUrl))
    if (config.renew) urlParameters.put("renew", "true")
    populateUrlAttributeMap(urlParameters)
    if (customParameters != null) urlParameters ++= customParameters
    val suffix = config.validateUri
    val buffer = new StringBuilder(urlParameters.size * 10 + config.casServer.length + suffix.length() + 1)
    buffer.append(config.casServer).append(suffix)

    var i = 0
    urlParameters foreach {
      case (key, value) =>
        if (value != null) {
          i += 1
          buffer.append(if (i == 1) "?" else "&")
          buffer.append(key)
          buffer.append("=")
          buffer.append(value)
        }
    }
    buffer.toString
  }
  /**
   * Encodes a URL using the URLEncoder format.
   */
  protected def encodeUrl(url: String): String = {
    if (url == null) null
    URLEncoder.encode(url, "UTF-8")
  }
  /**
   * Parses the response from the server into a CAS Assertion.
   * @throws TicketValidationException
   */
  protected def parseResponse(ticket: String, response: String): Assertion

  /**
   * Contacts the CAS Server to retrieve the response for the ticket validation.
   */
  protected def retrieveResponse(validationUrl: URL, ticket: String): String = {
    return HttpUtils.getResponseText(validationUrl, hostnameVerifier, encoding)
  }

  def validate(ticket: String, service: String): Assertion = {
    val validationUrl = constructValidationUrl(ticket, service)
    debug(s"Constructing validation url: $validationUrl")
    try {
      debug("Retrieving response from server.")
      val serverResponse = retrieveResponse(new URL(validationUrl), ticket)

      if (serverResponse == null) throw new TicketValidationException("The CAS server returned no response.")
      debug(s"Server response: $serverResponse")
      return parseResponse(ticket, serverResponse)
    } catch {
      case e: MalformedURLException => throw new TicketValidationException(e.getMessage())
    }
  }
  /**
   * Get an instance of an XML reader from the XMLReaderFactory.
   *
   */
  def xmlReader: XMLReader = XMLReaderFactory.createXMLReader()
  /**
   * Retrieve the text for a group of elements. Each text element is an entry
   * in a list.
   * <p>
   * This method is currently optimized for the use case of two elements in a list.
   *
   */
  def getTextForElements(xmlAsString: String, element: String): List[String] = {
    val elements = new collection.mutable.ListBuffer[String]
    val reader = xmlReader

    val handler = new DefaultHandler() {

      private var foundElement = false

      private var buffer = new StringBuilder()

      override def startElement(uri: String, localName: String, qName: String, attributes: Attributes): Unit = {
        if (localName.equals(element)) this.foundElement = true
      }

      override def endElement(uri: String, localName: String, qName: String): Unit = {
        if (localName.equals(element)) {
          this.foundElement = false
          elements += this.buffer.toString
          this.buffer = new StringBuilder()
        }
      }

      override def characters(ch: Array[Char], start: Int, length: Int): Unit = {
        if (this.foundElement) this.buffer.append(ch, start, length)
      }
    }

    reader.setContentHandler(handler)
    reader.setErrorHandler(handler)

    try {
      reader.parse(new InputSource(new StringReader(xmlAsString)))
      elements.toList
    } catch {
      case e: Exception => {
        error("parse error", e)
        null
      }
    }
  }
  /**
   * Retrieve the text for a specific element (when we know there is only
   * one).
   */
  def getTextForElement(xmlAsString: String, element: String): String = {
    val reader = xmlReader
    val builder = new StringBuilder()

    val handler = new DefaultHandler() {

      private var foundElement = false

      override def startElement(uri: String, localName: String, qName: String, attributes: Attributes): Unit = {
        if (localName.equals(element)) this.foundElement = true
      }

      override def endElement(uri: String, localName: String, qName: String): Unit = {
        if (localName.equals(element)) this.foundElement = false
      }

      override def characters(ch: Array[Char], start: Int, length: Int): Unit = {
        if (this.foundElement) builder.append(ch, start, length)
      }
    }

    reader.setContentHandler(handler)
    reader.setErrorHandler(handler)

    try {
      reader.parse(new InputSource(new StringReader(xmlAsString)))
      builder.toString()
    } catch {
      case e: Exception => {
        error("parse error", e)
        null
      }
    }
  }

}

class Cas20ServiceTicketValidator extends AbstractTicketValidator {

  protected override def parseResponse(ticket: String, response: String): Assertion = {
    val error = getTextForElement(response, "authenticationFailure")
    if (Strings.isNotBlank(error)) { throw new TicketValidationException(error) }
    val principal = getTextForElement(response, "user")

    if (Strings.isEmpty(principal)) throw new TicketValidationException("No principal was found in the response from the CAS server.")
    val attributes = extractCustomAttributes(response)
    new AssertionBean(principal, ticket, null, attributes)
  }

  /**
   * Default attribute parsing of attributes that look like the following:
   * &ltcas:attributes&gt
   * &ltcas:attribute1&gtvalue&lt/cas:attribute1&gt
   * &ltcas:attribute2&gtvalue&lt/cas:attribute2&gt
   * &lt/cas:attributes&gt
   * <p>
   * This code is here merely for sample/demonstration purposes for those wishing to modify the CAS2
   * protocol. You'll probably want a more robust implementation or to use SAML 1.1
   *
   * @param xml
   *          the XML to parse.
   * @return the map of attributes.
   */
  protected def extractCustomAttributes(xml: String): Map[String, Any] = {
    val pos1 = xml.indexOf("<cas:attributes>")
    val pos2 = xml.indexOf("</cas:attributes>")

    if (pos1 == -1) Map.empty
    else {
      val attributesText = xml.substring(pos1 + 16, pos2)

      val attributes = new collection.mutable.HashMap[String, Any]
      val br = new BufferedReader(new StringReader(attributesText))

      val attributeNames = new collection.mutable.ListBuffer[String]
      try {
        var line = br.readLine()
        while (line != null) {
          val trimmedLine = line.trim()
          if (trimmedLine.length() > 0) {
            attributeNames += (trimmedLine.substring(trimmedLine.indexOf(":") + 1, trimmedLine.indexOf(">")))
          }
          line = br.readLine()
        }
        br.close()
      } catch {
        case e: Exception => // ignore
      }

      attributeNames.foreach { name =>
        val values = getTextForElements(xml, name)
        if (values.size == 1) {
          attributes.put(name, values(0))
        } else {
          attributes.put(name, values)
        }
      }
      attributes.toMap
    }
  }
}