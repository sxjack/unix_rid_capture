# WiFi RID capture
A program that uses libpcap to capture ASTM F3411 / ASD-STAN 4709-002 UAV direct remote identification signals transmitted over WiFi.

Requires 
  * WiFi hardware capable of being put into monitor mode,
  * libpcap-dev,
  * opendroneid.c and opendroneid.h from [opendroneid](https://github.com/opendroneid/opendroneid-core-c/tree/master/libopendroneid).

The output is in json format. An perl script is provided which converts the json into gpx files suitable for Google Earth.

Tested using an rtl8812au based WiFi dongle.
