# simple-ping
A simple ping (networking utility) program.
Ping programs use ICMP echo requests to prompt an echo reply from the host.
The round trip times and some summary statistics are then reported.
#### Motivation
This personal challenge was motivated by Cloudflare's 2020 Systems Internship [Application](https://github.com/cloudflare-internship-2020/internship-application-systems).
Although I never got to submit this, it was still really interesting to learn the things required to make this.
## Compilation
A Makefile was created such that you can run `make` and it will create the binary file titled 'ping'.
## Usage
```
sudo ./ping destination
```
where the `destination` argument can be the hostname or IP address.
Use (Ctrl + C) or any interrupt signal to end the program and receive summary statistics.
#### Options
**-t ttl** set the IP time-to-live. Default 255. \
**-i interval** set the interval between sending packets. \
## Output
```
user:~/simple-ping$ sudo ./ping -t 9 -i 0.5 google.com 
44 bytes from google.com: icmp_seq=1 ttl=57 time=21.529
44 bytes from google.com: icmp_seq=2 ttl=57 time=19.554
44 bytes from google.com: icmp_seq=3 ttl=57 time=19.123
^C
--- google.com ping statistics ---
3 packets transmitted, 3 received
rtt min/avg/max/stddev = 19.123/20.069/21.529/1.048 ms
```
## Credits
This project: https://github.com/davidgatti/How-to-Deconstruct-Ping-with-C-and-NodeJS and its awesome readme was so helpful in making the learning process really great! \
Of course, Wikipedia was a huge help: [ping (network utitlity)](https://en.wikipedia.org/wiki/Ping_(networking_utility)).
