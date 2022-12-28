#
# Created for completeness, but don't bother with it.
# Just edit rid_capture.h file and use the Makefile.
#

cmake_minimum_required(VERSION 3.16)

project(rid_capture)
set(VERSION 0.95)

#
# Use the bluez library.
set(bluez_sniffer 1)
# Or use an nRF sniffer.
set(nrf_sniffer 0)
# Use the pcap library.
set(enable_pcap 1)
# Handle French beacon IDs.
set(id_france 1)
# Create a FlightAware aircraft.json output file. 
set(fa_export 1)
#
set(asterix 0)
#
set(verify 0)
#
set(use_curses 0)

#
configure_file(rid_capture.h.in rid_capture.h)

set(cmake_c_flags "-Wall -Wno-parentheses -Wno-deprecated-declarations")
#

set(rid_capture_source rid_capture.c)
set(base_libraries m c)
set(rcap_libraries ${base_libraries})

if(${id_france})
  set(rid_capture_source ${rid_capture_source} france.c)
endif()

if(${verify})
  set(rid_capture_source ${rid_capture_source} verify.c)
endif()

if(${bluez_sniffer})
  set(rid_capture_source ${rid_capture_source} bluez_sniffer.c)
  set(rcap_libraries bluetooth ${rcap_libraries})
endif()

if(${nrf_sniffer})
  set(rid_capture_source ${rid_capture_source} nrf_sniffer.c)
endif()

if(${fa_export})
  set(rid_capture_source ${rid_capture_source} export.c)
endif()

if(${asterix})
  set(rid_capture_source ${rid_capture_source} asterix.c)
endif()

if(${verify})
  set(rid_capture_source ${rid_capture_source} verify.c)
  set(rcap_libraries gcrypt ${rcap_libraries})
endif()

if(${use_curses})
  set(rcap_libraries ncurses ${rcap_libraries})
endif()

if(${enable_pcap})
  set(rcap_libraries pcap ${rcap_libraries})
endif()

set(rid_capture_source ${rid_capture_source} opendroneid.c)

add_executable(rid_capture
  ${rid_capture_source})
target_link_libraries(rid_capture ${rcap_libraries})
#
add_executable(nrf_sniffer nrf_sniffer.c)
target_link_libraries(nrf_sniffer ${base_libraries})
set_target_properties(nrf_sniffer PROPERTIES COMPILE_FLAGS "-DSTANDALONE=1")
#
add_executable(bluez_sniffer bluez_sniffer.c)
target_link_libraries(bluez_sniffer bluetooth ${base_libraries})
set_target_properties(bluez_sniffer PROPERTIES COMPILE_FLAGS "-DSTANDALONE=1")
#

