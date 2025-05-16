#!/bin/bash

# activate the virtual environment
conda activate BASIC

# give permission to access the serial port in linux for Pico Key
sudo chmod a+rw /dev/ttyACM0

# Check if QT_QPA_PLATFORM is set to xcb
if [ "$QT_QPA_PLATFORM" != "xcb" ]; then
    export QT_QPA_PLATFORM=xcb
fi

clear

# Run the main.py script
python3 main.py

# clear