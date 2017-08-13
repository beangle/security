package org.beangle.security.session.util

object UpdateDelayGeneratorTest {
  def main(args: Array[String]) {
    val generator = new UpdateDelayGenerator()
    println(generator.generateDelaySeconds)
  }
}