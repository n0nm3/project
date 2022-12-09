#!/bin/bash

YES=1


echo > /dev/tcp/localhost/22 && echo "$YES" || echo 'NOP'

echo "$YES" > /dev/tcp/localhost/1500 || echo 'Na'
