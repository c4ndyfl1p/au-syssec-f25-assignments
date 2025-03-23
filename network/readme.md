### Task 1: Encrypted covert channel

For this part, you will need to have some familiarity with the IP protocol to write low-level networking code using a library. Suggestions are the `libnet/libpcap` library in the C programming language or the equivalent `socket` package in Python.

We assume the following scenario: a whistleblower inside a network needs to transmit sensitive information to the outside, but without being detected by a draconian firewall. The firewall is configured to not allow much traffic to pass, but the system administrator has allowed some types of packets to go through because they can be used for debugging purposes. Our whistleblower has then decided to send non-standard ICMP packets containing encrypted data, in hope they can claim software error and plausibly deny the transmission in case they are detected.

The objective of this task is to implement an one-way encrypted covert channel using the [ICMP](https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol) (Internet Control Message Protocol) protocol.
Communication is one-way to follow the typical use case of covert channels for _exfiltration_ of sensitive data.
ICMP is an error-reporting protocol that network devices use to inform of error messages to the source IP address when network problems prevent an IP packet to be delivered.
The most familiar contact we have with the ICMP protocol is the `ping` tool using the `Echo Request` and `Echo Reply` messages. While these packets are typically small, it is not well-known that ICMP packets can carry much larger pieces of data.

You will implement client/server programs to exchange encrypted covert channel through the network. For this, use ICMP messages with type `47` (among the reserved numbers). The client program should receive a destination IP address from the command-line to transmit messages and wait for input from the keyboard at the client-side. The server program should listen to the network for such messages and print them in the console as they arrive. For encryption, you are free to use a preshared symmetric key to protect the transmitted payload. Choose algorithms and modes of operation wisely.

![Screenshot of a possible solution](icmp-covert-channel.png)

###
Instructions to run the code on debian based systems-

## Files explained:
All (solution) code resides in :
/home/alex/syssec/au-syssec-f25-assignments/network

At that level:
server.py - has server code
client.py - has client code
aes_crypto.py - has enc/dec functions
use_crypto.py - (can be ignored) sanity checks that crypo is working right


## How to run the code:
1. download solution code

2. cd into the folder
`cd au-syssec-f25-assignments`
(please make sure to stay at this level while running the rest if the steps)

3. make a venv(dealers choice- however you manage virtual envs)

4. activate it(however you manage your virtual envs)

5. Install dependencies
`pip3 install scapy`
`pip3 install pycryptodome`

6. Run server.
Note: scapy needs elevated priveledges to send and sniff packages. You can read throuh the code to make sure nothing harmful going on. 
`sudo $(which python3) network/server.py`


7. Run Client
Note: same as previous. Elevated privledge needed to send packets
`sudo $(which python3) network/client.py`

Screenshot:
![screenshot](image.png)


# Troubleshooting notes:

1. I tested this on my local machine using loopback IP, and hence the loopback interface. My loopback interface is called "lo", and this can be named differently on differnt devices. server.py line 33 specifies that as the interface to listen on.

`sniff(filter="icmp ", prn=icmp_callback, store=0, iface="lo") 
`

If the code does not work for some reason, try checking your specific loopback interface name

`ifconfig` on ubuntu, will show interfaces.

`sniff(filter="icmp ", prn=icmp_callback, store=0, iface="<your_interface_name>") `

2. If you test on 2 different devices, please change the interface name accordingly in the last line in server.py


# Citations and references:
1. https://thepacketgeek.com/scapy/ for a really well explained beginner friendly introduction to scapy. I was a bit lost before that

2. https://scapy.net/  < 3 < 3

3. ChatGPT for tasks i did not want to look up python docs for(and also scapy docs for, but honesty scapy is just so intuitive < 3), also writing enc/dec code. 