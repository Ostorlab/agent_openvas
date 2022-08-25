#!/usr/bin/env bash

echo "Updating NVTs..."
mkdir -p /usr/local/var/run/
chown -R openvas-sync:openvas-sync  /usr/local/var/run/
su -c "greenbone-nvt-sync" openvas-sync
su -c "rsync --compress-level=9 --links --times --omit-dir-times --recursive --partial --quiet rsync://feed.community.greenbone.net:/nvt-feed /usr/local/var/lib/openvas/plugins" openvas-sync
#sleep 5

#echo "Updating CERT data..."
#su -c "/cert-data-sync.sh" openvas-sync
#sleep 5

#echo "Updating SCAP data..."
#su -c "/scap-data-sync.sh" openvas-sync
