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

class Cas20TicketValidator extends AbstractTicketValidator {

  protected[cas] override def parseResponse(ticket: String, response: String): Assertion = {
    val reader = this.xmlReader
    reader.setFeature("http://xml.org/sax/features/namespaces", false)
    val handler = new ServiceXmlHandler()
    reader.setContentHandler(handler)
    reader.parse(new InputSource(new StringReader(response)))
    handler.assertion
  }

  /**
   * Get an instance of an XML reader from the XMLReaderFactory.
   *
   */
  def xmlReader: XMLReader = XMLReaderFactory.createXMLReader()

  class ServiceXmlHandler extends DefaultHandler {

    protected var currentText = new java.lang.StringBuffer()

    protected var authenticationSuccess = false
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

    def localName(qualifiedName: String): String = {
      Strings.substringAfter(qualifiedName, ":")
    }
    override def startElement(ns: String, lnm: String, qn: String, a: Attributes): Unit = {
      val ln = localName(qn)
      currentText = new StringBuffer()
      if (ln.equals("authenticationSuccess")) authenticationSuccess = true
      else if (ln.equals("authenticationFailure")) {
        authenticationSuccess = false
        errorCode = a.getValue("code")
        if (errorCode != null) errorCode = errorCode.trim()
      } else if (ln.equals("attribute")) {
        userMap.put(a.getValue("name"), a.getValue("value"))
      }
      if (authenticationSuccess) {
        if (ln.equals("proxies")) proxyFragment = true
        if (ln.equals("checkAliveTicket")) checkAliveFragment = true
      }
    }

    override def characters(ch: Array[Char], start: Int, length: Int): Unit = {
      currentText.append(ch, start, length)
    }

    override def endElement(ns: String, lnm: String, qn: String): Unit = {
      val ln = localName(qn)
      if (authenticationSuccess) {
        if (ln.equals("user")) user = currentText.toString().trim()
        if (ln.equals("proxyGrantingTicket")) pgtIou = currentText.toString().trim()
      } else if (ln.equals("authenticationFailure")) errorMessage = currentText.toString().trim()
      if (ln.equals("proxies")) proxyFragment = false
      else if (proxyFragment && ln.equals("proxy")) proxyList += currentText.toString().trim()
      if (ln.equals("checkAliveTicket")) {
        checkAliveFragment = false
        caKey = currentText.toString().trim()
      }
    }

    def assertion: Assertion = {
      if (authenticationSuccess) new AssertionBean(user, caKey, null, userMap.toMap)
      else throw new TicketValidationException(errorCode + ":" + errorMessage)
    }
  }
}