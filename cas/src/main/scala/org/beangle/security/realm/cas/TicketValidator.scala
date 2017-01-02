/*
 * Beangle, Agile Development Scaffold and Toolkit
 *
 * Copyright (c) 2005-2017, Beangle Software.
 *
 * Beangle is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Beangle is distributed in the hope that it will be useful.
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Beangle.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.beangle.security.realm.cas

import java.net.{ MalformedURLException, URL, URLEncoder }

import org.beangle.commons.logging.Logging
import org.beangle.commons.web.util.HttpUtils

import javax.net.ssl.HostnameVerifier

class TicketValidationException(message: String) extends Exception(message)

trait TicketValidator {

  @throws(classOf[TicketValidationException])
  def validate(ticket: String, service: String): String
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
    val buffer = new java.lang.StringBuilder(urlParameters.size * 10 + config.casServer.length + suffix.length() + 1)
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
  protected def parseResponse(ticket: String, response: String): String

  /**
   * Contacts the CAS Server to retrieve the response for the ticket validation.
   */
  protected def retrieveResponse(url: URL, ticket: String): String = HttpUtils.getResponseText(url, hostnameVerifier, encoding)

  def validate(ticket: String, service: String): String = {
    val validationUrl = constructValidationUrl(ticket, service)
    logger.debug(s"Constructing validation url: $validationUrl")
    try {
      logger.debug("Retrieving response from server.")
      val serverResponse = retrieveResponse(new URL(validationUrl), ticket)
      if (serverResponse == null) throw new TicketValidationException("The CAS server returned no response.")
      logger.debug(s"Server response: $serverResponse")
      parseResponse(ticket, serverResponse)
    } catch {
      case e: MalformedURLException => throw new TicketValidationException(e.getMessage())
    }
  }
}

import java.io.{ BufferedReader, StringReader }
import org.beangle.commons.lang.Strings
import org.xml.sax.helpers.XMLReaderFactory
import org.xml.sax.helpers.DefaultHandler
import org.xml.sax.Attributes
import org.xml.sax.XMLReader
import org.xml.sax.InputSource

class DefaultTicketValidator extends AbstractTicketValidator {

  protected[cas] override def parseResponse(ticket: String, response: String): String = {
    val reader = this.xmlReader
    reader.setFeature("http://xml.org/sax/features/namespaces", false)
    val handler = new ServiceXmlHandler(ticket)
    reader.setContentHandler(handler)
    reader.parse(new InputSource(new StringReader(response)))
    handler.preuser
  }

  /**
   * Get an instance of an XML reader from the XMLReaderFactory.
   *
   */
  def xmlReader: XMLReader = XMLReaderFactory.createXMLReader()

  class ServiceXmlHandler(ticket: String) extends DefaultHandler {

    private var currentText = new java.lang.StringBuffer()

    private var authenticationSuccess = false
    private var userMap = new collection.mutable.HashMap[String, Object]
    private var errorCode: String = _
    private var errorMessage: String = _
    private var pgtIou: String = _
    private var user: String = _
    private var proxyList = new collection.mutable.ListBuffer[String]

    def localName(qualifiedName: String): String = {
      Strings.substringAfter(qualifiedName, ":")
    }
    override def startElement(ns: String, lnm: String, qn: String, a: Attributes): Unit = {
      currentText = new StringBuffer()
      localName(qn) match {
        case "authenticationSuccess" => authenticationSuccess = true
        case "authenticationFailure" =>
          authenticationSuccess = false
          errorCode = a.getValue("code")
          if (errorCode != null) errorCode = errorCode.trim()
        case "attribute" => userMap.put(a.getValue("name"), a.getValue("value"))
        case _           =>
      }
    }

    override def characters(ch: Array[Char], start: Int, length: Int): Unit = {
      currentText.append(ch, start, length)
    }

    override def endElement(ns: String, lnm: String, qn: String): Unit = {
      val ln = localName(qn)
      ln match {
        case "user"                   => user = currentText.toString.trim()
        case "proxyGrantingTicket"    => pgtIou = currentText.toString.trim()
        case "authenticationFailure"  => errorMessage = currentText.toString.trim()
        case "proxy"                  => proxyList += currentText.toString.trim()
        case "attributes" | "proxies" =>
        case _                        => userMap.put(ln, currentText.toString.trim())
      }
    }

    def preuser: String = {
      if (authenticationSuccess) user
      else throw new TicketValidationException(errorCode + ":" + errorMessage)
    }
  }
}