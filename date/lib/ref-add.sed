/^# Packages using this file: / {
  s/# Packages using this file://
  ta
  :a
  s/ sh-utils / sh-utils /
  tb
  s/ $/ sh-utils /
  :b
  s/^/# Packages using this file:/
}
