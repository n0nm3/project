#!/bin/bash

YES=1

echo > /dev/udp/localhost/22 && echo '$YES' || echo 'NOP'


echo > /dev/tcp/localhost/22 && echo "$YES" || echo 'NOP'
