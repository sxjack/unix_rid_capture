# WiFi RID capture
A program that uses libpcap to capture ASTM F3411 / ASD-STAN 4709-002 UAV direct remote identification signals transmitted over WiFi and Bluetooth. 

Requires 
  * WiFi hardware capable of being put into monitor mode,
  * libpcap-dev (optional),
  * bluez (optional)
  * opendroneid.c and opendroneid.h from [opendroneid](https://github.com/opendroneid/opendroneid-core-c/tree/master/libopendroneid).

The output is in json format. An perl script is provided which converts the json into gpx files suitable for Google Earth.

Tested using an rtl8812au based WiFi dongle.

Probably won't receiver BT5 advertising.

If anybody runs this in the vicinity of an "Arrêté du 27 décembre 2019" French ID, I would appreciate the debug.txt.

### Command Line Options
  * `-w <WiFi device>`
  * `-x` WiFi device is already in monitor mode.
  * `-u` send the json output to UDP port 32001.

The UDP output can be read using netcat, `nc -lu 32001`.

## Getting Started

### Hardware and Driver

You need a WiFi card/dongle that can be put into monitor mode. If you are using an rtl8812au dongle you will need to build and install a third party driver which is a bit of a palaver. Modify the `monitor.sh` script as required until it is getting the hardware monitoring channel 6.

### Compile rid_capture

Install libpcap-dev and/or bluez. Make sure that all the options at the top of `rid_capture.h` are set correctly and type make. It may make things easier later on if you edit the default device name near the top of `rid_capture.c` to match your installation.

### Running rid_capture

`rid_capture` needs to be run as root or with cap_net_raw capabilities (`setcap cap_net_raw+eip rid_capture` as root).

Run rid_capture. If it suggests that you use the -x option do so. You can override the device name on the command line. The first line that it outputs will show you what device it is using. Control C stops the program.

rid_capture defaults to writing json to stdout. Capture this json to a file, e.g. `./rid_capture -x > rid_capture.txt` and then feed the json to the rid2gpx.pl script (`./scripts/rid2gpx.pl < rid_capture.txt`). If this works you will end up with a gpx file that Google Earth will display.

If nothing is transmitting WiFi RID, rid_capture will peridically put out debug reports saying how may WiFi packets it has seen. 
```
{ "debug" : "rx packets 92 (0)" }
```
If the program is seeing WiFi RID, the output will look like -
```
{ "mac" : "ac:67:b2:09:50:d4", "operator" : "GBR-OP-ZZZZZZZZZZZZ", "uav id" : "SERIAL NUMBER", "uav latitude" :    0.000000, "uav longitude" :    0.000000, "uav altitude" : -1000, "uav heading" : 361, "uav speed" : 255, "seconds" : 0, "base latitude" :    0.000000, "base longitude" :    0.000000, "unix time" : 1546300800 }
```





