/*
 * Copyright (C) 2005, The Beangle Software.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.beangle.security.realm.cas

import org.beangle.commons.lang.Strings
import org.beangle.commons.logging.Logging
import org.beangle.commons.net.http.HttpUtils
import org.xml.sax.helpers.DefaultHandler
import org.xml.sax.{Attributes, InputSource, XMLReader}

import java.io.StringReader
import java.net.URLEncoder
import javax.xml.parsers.SAXParserFactory

class TicketValidationException(message: String) extends Exception(message)

trait TicketValidator {

  @throws(classOf[TicketValidationException])
  def validate(ticket: String, service: String): CasResponse
}

object DefaultTicketValidator {

  def parse(response: String): CasResponse = {
    val reader = this.xmlReader
    reader.setFeature("http://xml.org/sax/features/namespaces", false)
    val handler = new ServiceXmlHandler()
    reader.setContentHandler(handler)
    reader.parse(new InputSource(new StringReader(response)))
    handler.result
  }

  /** Get an instance of an XML reader from the XMLReaderFactory.
   */
  private def xmlReader: XMLReader = {
    val parserFactory = SAXParserFactory.newInstance
    val parser = parserFactory.newSAXParser
    parser.getXMLReader
  }

  private final class ServiceXmlHandler extends DefaultHandler {
    private var currentText = new java.lang.StringBuffer()

    private var authenticationSuccess = false
    private val attributes = new collection.mutable.HashMap[String, String]
    private var errorCode: String = _
    private var errorMessage: String = _
    private var user: String = _

    private def localName(qualifiedName: String): String = {
      Strings.substringAfter(qualifiedName, ":")
    }

    /** 开始处理标签（attrs 包含标签的属性)
     *
     * @param ns    namespace
     * @param lnm   localName
     * @param qn    qualifiedName
     * @param attrs element attributes
     */
    override def startElement(ns: String, lnm: String, qn: String, attrs: Attributes): Unit = {
      currentText = new StringBuffer()
      localName(qn) match {
        case "authenticationSuccess" => authenticationSuccess = true
        case "authenticationFailure" =>
          authenticationSuccess = false
          errorCode = attrs.getValue("code")
          if (errorCode != null) errorCode = errorCode.trim()
        case "attribute" => attributes.put(attrs.getValue("name"), attrs.getValue("value"))
        case _ =>
      }
    }

    override def characters(ch: Array[Char], start: Int, length: Int): Unit = {
      currentText.append(ch, start, length)
    }

    /** 接收user，如果是其他标签排除部分忽略的，直接进入attributes
     *
     * @param ns  namespace
     * @param lnm localName
     * @param qn  qualified name
     */
    override def endElement(ns: String, lnm: String, qn: String): Unit = {
      localName(qn) match {
        case "user" => user = currentText.toString.trim()
        case "authenticationFailure" => errorMessage = currentText.toString.trim()
        case "serviceResponse" | "authenticationSuccess" | "attributes" | "proxies" | "proxyGrantingTicket" | "proxy" =>
        case ln =>
          val text = currentText.toString.trim()
          if Strings.isNotBlank(text) then attributes.put(ln, currentText.toString.trim())
      }
    }

    def result: CasResponse = {
      if (authenticationSuccess) CasResponse("success", Option(user), attributes.toMap, null)
      else CasResponse(errorCode, None, attributes.toMap, errorMessage)
    }
  }
}

/** Default Ticket Validator
 */
class DefaultTicketValidator extends TicketValidator, Logging {

  var config: CasConfig = _

  override def validate(ticket: String, service: String): CasResponse = {
    val validationUrl = constructValidationUrl(ticket, service)
    val r = HttpUtils.getText(validationUrl)
    logger.debug(s"Get ${validationUrl},and response is : ${r.getText}")
    if (r.isOk) {
      DefaultTicketValidator.parse(r.getText)
    } else {
      CasResponse("failure", None, Map.empty, r.getText)
    }
  }

  /** Constructs the URL to send the validation request to.
   */
  private def constructValidationUrl(ticket: String, serviceUrl: String): String = {
    val urlParameters = new collection.mutable.HashMap[String, String]
    urlParameters.put("ticket", ticket)
    if (null != serviceUrl) {
      urlParameters.put("service", URLEncoder.encode(serviceUrl, "UTF-8"))
    }
    val suffix = config.validateUri
    val buffer = new java.lang.StringBuilder(urlParameters.size * 10 + config.casServer.length + suffix.length() + 1)
    buffer.append(config.casServer).append(suffix)

    var i = 0
    urlParameters foreach {
      case (key, value) =>
        if (value != null) {
          i += 1
          buffer.append(if (i == 1) "?" else "&")
          buffer.append(key).append("=").append(value)
        }
    }
    buffer.toString
  }
}
