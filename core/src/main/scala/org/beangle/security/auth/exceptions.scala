package org.beangle.security.auth

import org.beangle.security.core.AuthenticationException

class BadCredentialsException(message:String,cause:Throwable) extends AuthenticationException(message,cause)

class LockedException (message:String,user:AnyRef) extends AuthenticationException(message,null){
  this.extraInfo=user
}

class DisabledException (message:String,user:AnyRef) extends AuthenticationException(message,null){
  this.extraInfo=user
}

class CredentialsExpiredException (message:String,user:AnyRef) extends AuthenticationException(message,null){
  this.extraInfo=user
}

class AccountExpiredException (message:String,user:AnyRef) extends AuthenticationException(message,null){
  this.extraInfo=user
}
