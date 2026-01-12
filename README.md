# debugping

A simple ping example made with [fasm2](https://github.com/tgrysztar/fasm2 "flat assembler 2") with a lot of verbose output! Only for those who (like me) are seeking to figure out how ICMP works on Linux.
It ships default in 'Ion Cannon mode' (iykwim), so be advised to always set ICMP_LOOP_DELAY with milisseconds value as poll interval limiter before lauching this:

```
 > ICMP_LOOP_DELAY=500 debugping example.com
```

Use 'CTRL+C' to exit and print status.

**Compile notes:** for folks who wants to compile it from source, all of those support macros are within this GitHub page! So, take a look around.
