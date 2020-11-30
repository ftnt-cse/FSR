#!/bin/bash
# Reads the number of days to keep the logs, then purges all log files modified before that period.

read -p "How many days for log retention ?:" LOG_RETENTION_DAYS

re='^[0-9]+$'
if ! [[ $LOG_RETENTION_DAYS =~ $re ]] ; then
   echo "error: Not a valid number" >&2; exit 1
fi

if crontab -u root -l|grep -q "find /var/log -type f -mtime"
then
    echo "Cron exists, updating..."
    (crontab -u root -l | sed '/\/var\/log -type/d') | crontab -u root -
fi

logpurge="1 1 * * 7 /usr/bin/find /var/log -type f -mtime +$LOG_RETENTION_DAYS -exec rm -f -v {} \; > /dev/null 2&>1"
(crontab -u root -l; echo "$logpurge" ) | crontab -u root -

echo "entry: $(crontab -u root -l|grep "find /var/log -type f -mtime") added"
