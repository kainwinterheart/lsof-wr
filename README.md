lsof-wr.pl
---

Usage example
===

$ sudo perl lsof-wr.pl | grep 437215508 # 437215508 - unix socket
fcgi-work 17610      www-data    5u     unix 0xffff8802b07db900        0t0  437215508 socket -> 0xffff8802b07d9b00[memcached,31182,/tmp/memcached.11211.sock]
