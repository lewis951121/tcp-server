socat -u -T60 TCP4-LISTEN:9999,reuseaddr,fork OPEN:/tmp/temp.log,create,append
