import org.beangle.parent.Dependencies.*
import org.beangle.parent.Settings.*

ThisBuild / organization := "org.beangle.security"
ThisBuild / version := "4.3.21"

ThisBuild / scmInfo := Some(
  ScmInfo(
    url("https://github.com/beangle/security"),
    "scm:git@github.com:beangle/security.git"
  )
)

ThisBuild / developers := List(
  Developer(
    id = "chaostone",
    name = "Tihua Duan",
    email = "duantihua@gmail.com",
    url = url("http://github.com/duantihua")
  )
)

ThisBuild / description := "The Beangle Data Library"
ThisBuild / homepage := Some(url("https://beangle.github.io/security/index.html"))

val beangle_commons = "org.beangle.commons" % "beangle-commons" % "5.6.17"
val beangle_jdbc = "org.beangle.jdbc" % "beangle-jdbc" % "1.0.2"
val beangle_serializer = "org.beangle.serializer" % "beangle-serializer" % "0.1.10"
val beangle_cache = "org.beangle.cache" % "beangle-cache" % "0.1.9"
val beangle_web = "org.beangle.web" % "beangle-web" % "0.4.12"

lazy val root = (project in file("."))
  .settings(
    name := "beangle-security",
    common,
    libraryDependencies ++= Seq(beangle_commons, logback_classic % "test", scalatest, mockito),
    libraryDependencies ++= Seq(beangle_cache, beangle_jdbc, beangle_serializer),
    libraryDependencies ++= Seq(beangle_web, protobuf)
  )
