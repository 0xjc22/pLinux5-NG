group "default" {
  targets = ["pld"]
}

target "pld" {
  context    = "."
  dockerfile = "Dockerfile"
  target     = "final"
  output     = ["type=local,dest=out"]
}