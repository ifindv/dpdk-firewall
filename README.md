# A Firewall Practice Based on DPDK

## BUILD
- first time build in a new environment:
```
source build.sh
```

- for debug version:
```
source build.sh debug
```

- latter:
```
ninja -C build
```

## DEPLOY
- list all network interfaces which can be bind to DPDK driver:
```
./deploy.sh
```

- then select 2 network interfaces to bind:
```
./deploy.sh <NIC1> <NIC2>
```

## RUN
- firstly, some environment variables should be set before run firewall application:
```
source run.sh
```

- then you can run app by:
```
dpdk-firewall -l 0-3 -n 4
```

- if you want to control or show app's inner stat, just run telnet, login with username 'ifindv' and password 'ifindv'. 
  the password for privileged account is 'superman:
```
telnet <localhost> 8000
```

## ABOUT AUTHOR
- author: ifindv
- email: ifindv@gmail.com
