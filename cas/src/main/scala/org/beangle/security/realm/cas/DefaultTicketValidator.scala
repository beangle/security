/*
 * Beangle, Agile Development Scaffold and Toolkit
 *
 * Copyright (c) 2005-2015, Beangle Software.
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

import java.io.{ BufferedReader, StringReader }
import org.beangle.commons.lang.Strings
import org.xml.sax.helpers.XMLReaderFactory
import org.xml.sax.helpers.DefaultHandler
import org.xml.sax.Attributes
import org.xml.sax.XMLReader
import org.xml.sax.InputSource

class DefaultTicketValidator extends AbstractTicketValidator {

  protected[cas] override def parseResponse(ticket: String, response: String): Assertion = {
    val reader = this.xmlReader
    reader.setFeature("http://xml.org/sax/features/namespaces", false)
    val handler = new ServiceXmlHandler(ticket)
    reader.setContentHandler(handler)
    reader.parse(new InputSource(new StringReader(response)))
    handler.assertion
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

    def assertion: Assertion = {
      if (authenticationSuccess) new AssertionBean(user, ticket, null, userMap.toMap)
      else throw new TicketValidationException(errorCode + ":" + errorMessage)
    }
  }
}