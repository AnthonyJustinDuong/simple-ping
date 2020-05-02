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
sudo ./ping host
```
where the `host` argument can be the hostname or IP address. \
**Flags coming soon** \
Use (ctrl + C) or any interrupt signal to end the program and receive summary statistics.
## Output
Sample image coming soon.
## Credits
This project: https://github.com/davidgatti/How-to-Deconstruct-Ping-with-C-and-NodeJS and its awesome readme was so helpful in making the learning process really great! \
Of course, Wikipedia was a huge help: [ping (network utitlity)](https://en.wikipedia.org/wiki/Ping_(networking_utility)).
