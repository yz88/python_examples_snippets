#!/usr/bin/env python
# -*- coding: utf-8 -*-

# AMAZON DASH - DESPERADOS
# MAC: 78:E1:03:47:A7:D8
#
# AMAZON-DASH-HEINEKEN
# MAC: 38:F7:3D:28:A8:18
#
#
# https://blog.thesen.eu/aktuellen-dash-button-oder-ariel-etc-von-amazon-jk29lp-mit-dem-raspberry-pi-nutzen-hacken/
#
# LED Verhalten des Dash-Buttons:
# Zur Fehlersuche habe ich hier noch kurz das LED Blink/Leuchverhalten notiert, soweit es sich mir erschlossen hat.
# LED leuchtet nach einem Tastendruck
# nur rot -> Button ist nicht konfiguriert (oder hat das Deaktivierungskommando bekommen und ist somit nicht mehr konfiguriert).
# blau -> Button wurde lange gedrückt und ist im Konfigurationsmodus für die Amazon App
# weiss, dann grün -> Button hat erfolgreich eine Bestellung bei Amazon getätigt.
# weiss, dann rot -> Button hat sich ins WLAN eingeloggt, konnte aber keine Bestellung bei Amazon auslösen.
#
# Der „Hack“ auf dem Pi:
# Die üblichen „Hacks“ beruhen auf dem Verhalten des Dash Buttons. Der Button ist ohne Tastendruck in einem Schalfmodus und nicht im WLAN. Wenn man die Taste drückt, loggt sich der Button im WLAN ein. Diesen Vorgang kann man im Netzwerk erkennen und darauf reagieren. Es finden sich im Netz eine Menge python Scripte, die dies für ARP leisten. Diese Protokolle funktionieren mit dem aktuellen Button nicht mehr, da dieser per bootp arbeitet.
# Bevor wir loslegen können, muss man zwei Pakete nachladen; dies geht per:
# sudo apt-get install scapy
# sudo apt-get install tcpdump
# Nach der Installation läuft das folgende Script; einfach als dash.py ablegen. Der Code ist an einigen Beispielen im Netz orientiert und macht den Pi zu einem Netzwerksniffer, der auf das passende Paket wartet.
#

import datetime
import logging

# Constants
timespan_threshhold = 3

# Globals
desp_lastpress = datetime.datetime(1970,1,1)
hein_lastpress = datetime.datetime(1970,1,1)

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *


def button_pressed_dash_descperados():
  global desp_lastpress
  thistime = datetime.datetime.now()
  desp_timespan = thistime - desp_lastpress
  if desp_timespan.total_seconds() > timespan_threshhold:
    current_time = datetime.datetime.strftime(thistime, '%Y-%m-%d %H:%M:%S')
    print 'Dash button DESPERADOS pressed at ' + current_time
    # another action

  desp_lastpress = thistime

def button_pressed_dash_heineken():
  global hein_lastpress
  thistime = datetime.datetime.now()
  hein_timespan = thistime - hein_lastpress
  if hein_timespan.total_seconds() > timespan_threshhold:
    current_time = datetime.datetime.strftime(thistime, '%Y-%m-%d %H:%M:%S')
    print 'Dash button HEINEKEN pressed at ' + current_time
    # another action

  hein_lastpress = thistime

def udp_filter(pkt):
  options = pkt[DHCP].options
  for option in options:
    if isinstance(option, tuple):
      if 'requested_addr' in option:
        # we've found the IP address, which means its the second and final UDP request, so we can trigger our action
        mac_to_action[pkt.src]()
        break

# WICHTIG: In dem Script die MAC des eigenen Dash Buttons eintragen und auf KLEINSCHREIBUNG der Buchstaben achten.
mac_to_action = {'78:e1:03:47:a7:d8' : button_pressed_dash_descperados, '38:f7:3d:28:a8:18' : button_pressed_dash_heineken}
mac_id_list = list(mac_to_action.keys())

print "Waiting for a button press..."
sniff(prn=udp_filter, store=0, filter="udp", lfilter=lambda d: d.src in mac_id_list)

if __name__ == "__main__":
  main()
