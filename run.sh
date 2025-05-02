#!/bin/bash

# activate the virtual environment
conda activate BASIC
sudo chmod a+rw /dev/ttyACM0

# Check if QT_QPA_PLATFORM is set to xcb
if [ "$QT_QPA_PLATFORM" != "xcb" ]; then
    export QT_QPA_PLATFORM=xcb
fi

clear

# Run the main.py script
python3 main.py