# answer at multiple ports (9898 & 9999)
iptables -F
iptables -I INPUT -j ACCEPT

iptables -t nat PREROUTING -p tcp --dport 9898 -j REDIRECT --to-ports 9999
