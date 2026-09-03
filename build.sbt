import org.beangle.parent.Dependencies.*
import org.beangle.parent.Settings.*

organization := "org.beangle.security"
version := "4.5.2-SNAPSHOT"

scmInfo := Some(
  ScmInfo(
    uri("https://github.com/beangle/security"),
    "scm:git@github.com:beangle/security.git"
  )
)

developers := List(
  Developer(
    id = "chaostone",
    name = "Tihua Duan",
    email = "duantihua@gmail.com",
    url = uri("http://github.com/duantihua")
  )
)

description := "The Beangle Data Library"
homepage := Some(uri("https://beangle.github.io/security/index.html"))

val beangle_commons = "org.beangle.commons" % "beangle-commons" % "6.3.2"
val beangle_jdbc = "org.beangle.jdbc" % "beangle-jdbc" % "1.1.14"
val beangle_cache = "org.beangle.cache" % "beangle-cache" % "0.1.21"
val beangle_web = "org.beangle.web" % "beangle-web" % "0.7.9"
val beangle_serializer = "org.beangle.serializer" % "beangle-serializer" % "0.1.28"

lazy val root = (project in file("."))
  .settings(
    name := "beangle-security",
    common,
    Compile / mainClass := Some("org.beangle.security.realm.ldap.Main"),
    libraryDependencies ++= Seq(beangle_commons, beangle_cache, beangle_jdbc, beangle_web, slf4j, protobuf),
    libraryDependencies ++= Seq(logback_classic % "test", beangle_serializer % "test", scalatest, mockito)
  )
