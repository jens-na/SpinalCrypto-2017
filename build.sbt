name := "SpinalCrypto"

organization := "com.github.spinalhdl"

version := "1.0"

scalaVersion := "2.11.6"

EclipseKeys.withSource := true

libraryDependencies ++= Seq(
  "com.github.spinalhdl" % "spinalhdl-core_2.11" % "latest.release",
  "com.github.spinalhdl" % "spinalhdl-lib_2.11" % "latest.release",
  "org.scalatest" % "scalatest_2.11" % "2.2.1"
)