# debugping

A simple ping example made with [fasm2](https://github.com/tgrysztar/fasm2 "flat assembler 2") with a lot of verbose output! Only for those who (like me) are seeking to figure out how ICMP works on Linux.
It ships default in 'Ion Cannon mode' (iykwim), so be advised to always set ICMP_LOOP_DELAY with milisseconds value as poll interval limiter before lauching this:

```
 > ICMP_LOOP_DELAY=500 debugping example.com
```

Also, one can override the default 5 seconds reply wait timeout as follows (wait time in milisseconds):

```
 > ICMP_PROBE_TIMEOUT=2000 ICMP_LOOP_DELAY=500 debugping example.com
```

There is also an option to keep send periodicity in sync with provided (and required) loop delay (enable with '1'):
```
 > ICMP_LOOP_DELAY=1000 ICMP_SYNC_WAIT_WITH_REPLY=1 debugping example.com
```
The above will keep as tight as possible to 1000 ms each echo request sent.

Use 'CTRL+C' to exit and print status.

To install, just copy the binary under release folder to your preferred bin path location (i.e., /usr/bin or ~/.local/bin) which must be included under PATH environment.

**Compile notes:** for folks who wants to compile it from source, all of those support macros are within this GitHub page! So, take a look around.
