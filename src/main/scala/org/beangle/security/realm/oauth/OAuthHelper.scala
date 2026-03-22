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

package org.beangle.security.realm.oauth

import org.beangle.commons.lang.{Charsets, Strings}
import org.beangle.commons.net.http.{HttpUtils, Request, Response}

import java.net.URLEncoder
import java.security.MessageDigest
import java.util.Base64

/** OAuth 2.0 授权码流程辅助类，支持 PKCE */
class OAuthHelper(val config: OAuthConfig) {

  /**
   * 构建授权请求的完整 URL，包含必要的参数及 PKCE 的 code_challenge。
   * 用于将用户重定向到 OAuth 服务提供商的授权页面。
   *
   * @param redirectUri  授权成功后的回调地址
   * @param codeVerifier codeVerifier
   * @param state        可选，用于防止 CSRF 攻击的状态参数
   * @return AuthorizeResult 包含完整授权 URL 和 code_verifier（换取 token 时需传入）
   */
  def buildAuthorizeUrl(redirectUri: String, state: Option[String] = None): AuthorizeRequest = {
    val codeVerifier = generateCodeVerifier()
    val codeChallenge = generateCodeChallenge(codeVerifier)

    val params = new collection.mutable.ArrayBuffer[(String, String)]
    params.addOne(("client_id", config.clientId))
    params.addOne(("redirect_uri", redirectUri))
    params.addOne(("response_type", "code"))
    params.addOne(("code_challenge", codeChallenge))
    if (state.nonEmpty) {
      params.addOne(("state", state.get))
    }
    params += (("code_challenge_method", "S256"))
    config.scope.filter(Strings.isNotBlank).foreach(s => params += (("scope", s)))

    val queryString = params.map { case (k, v) => k + "=" + URLEncoder.encode(v, "UTF-8") }.mkString("&")
    val separator = if (config.authorizeUrl.contains("?")) "&" else "?"
    AuthorizeRequest(config.authorizeUrl + separator + queryString, codeVerifier)
  }

  /**
   * 使用授权码换取访问令牌（含 PKCE 的 code_verifier）。
   *
   * @param code         授权码（从回调请求中获取）
   * @param codeVerifier buildAuthorizeUrl 返回的 code_verifier，需在回调时从 session 等存储中取出
   * @return HTTP 响应，成功时 body 通常为 JSON，包含 access_token、token_type、expires_in 等
   */
  def getToken(code: String, codeVerifier: String): Response = {
    assert(Strings.isNotBlank(code))
    assert(Strings.isNotBlank(codeVerifier))

    val formData = Seq(
      "grant_type" -> "authorization_code",
      "client_id" -> config.clientId,
      "code" -> code,
      "code_verifier" -> codeVerifier
    )
    val request = Request.asForm(formData)
    HttpUtils.post(config.tokenUrl, request)
  }

  private def generateCodeVerifier(): String = {
    val random = new java.security.SecureRandom()
    val bytes = new Array[Byte](32)
    random.nextBytes(bytes)
    Base64.getUrlEncoder.withoutPadding().encodeToString(bytes)
  }

  private def generateCodeChallenge(codeVerifier: String): String = {
    val digest = MessageDigest.getInstance("SHA-256")
    val hash = digest.digest(codeVerifier.getBytes(Charsets.UTF_8))
    Base64.getUrlEncoder.withoutPadding().encodeToString(hash)
  }

}

/** 授权请求结果，包含重定向 URL 和 PKCE 用的 code_verifier */
case class AuthorizeRequest(url: String, codeVerifier: String)
