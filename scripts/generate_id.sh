#!/bin/sh


# Generates new ID for controls. Run it when adding a new control and set the ouput as the 'id' field


# Get current highest id from all controls
HIGHEST_ID=$(grep \"id\": ../controls/*.json -h | cut -d "-" -f 2 | sort | tail -n1 |   sed 's/"//g;s/0//g' | tr -d ,)

NEW_ID=$(echo $(($HIGHEST_ID + 1)))


[ $NEW_ID -lt 10 ] && NEW_ID="0$NEW_ID"

[ $NEW_ID -lt 100 ] && NEW_ID="0$NEW_ID"

[ $NEW_ID -lt 1000 ] && NEW_ID="0$NEW_ID"

echo "C-$NEW_ID"