leaky-jail
==========

Install dependencies:
```
libseccomp-dev
```

Compile:
```
make
```

Use:
```
./ljail <program>
```

Example:
```
./ljail ./test
```

The jailed program has rights to open /lib/x86_64-linux-gnu/libc.so.6,
/etc/ld.so.cache, and it's own executable. The flags it can use are O_RDONLY
and O_CLOEXEC.
