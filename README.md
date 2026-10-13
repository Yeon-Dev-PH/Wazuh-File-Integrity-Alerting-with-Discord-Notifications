# Wazuh File Integrity Alerting with Discord Notifications

A small lab that detects file creation, modification and deletion on a Windows endpoint with Wazuh, raises those events to high severity using custom rules, and posts them to a Discord channel.

Tested on Wazuh 4.14.8 with a Kali Linux VM as the server and a Windows 11 Pro PC as the monitored agent.

## How it works

```
Windows agent (FIM, realtime)
        |  events on port 1514
        v
Wazuh manager (Kali) --> custom rules 100100 / 100101 / 100102
        |                         |
        v                         v
Wazuh indexer + dashboard     Integrator (level >= 12)
                                  |
                                  v
                          custom-discord script --> Discord webhook
```

| Event | Built-in rule | Custom rule | Level |
| --- | --- | --- | --- |
| File created | 554 (level 5) | 100100 | 12 |
| File modified | 550 (level 7) | 100101 | 12 |
| File deleted | 553 (level 7) | 100102 | 14 |

## Prerequisites

- A working Wazuh server (manager, indexer, dashboard) and at least one enrolled agent.
- Root access on the server and Administrator access on the Windows agent.
- A Discord server where you can create a webhook.
- Outbound internet access from the Wazuh server to `discord.com`.

## Setup

### 1. Watch a folder on the Windows agent

On the Windows PC, create the test folder and edit the agent config:

```powershell
mkdir C:\FIMTest
notepad "C:\Program Files (x86)\ossec-agent\ossec.conf"
```

Inside the `<syscheck>` section, next to the other `<directories>` lines, add:

```xml
<directories realtime="yes" check_all="yes" report_changes="yes">C:\FIMTest</directories>
```

Save the file and restart the agent:

```powershell
Restart-Service WazuhSvc
```

`realtime="yes"` reports changes immediately instead of waiting for the periodic scan (every 12 hours by default).

### 2. Add the custom rules on the server

Open `/var/ossec/etc/rules/local_rules.xml` and add:

```xml
<group name="syscheck,custom,">

  <rule id="100100" level="12">
    <if_sid>554</if_sid>
    <field name="file" type="pcre2">(?i)fimtest</field>
    <description>ALERT: New file created in watched folder C:\FIMTest</description>
  </rule>

  <rule id="100101" level="12">
    <if_sid>550</if_sid>
    <field name="file" type="pcre2">(?i)fimtest</field>
    <description>ALERT: File modified in watched folder C:\FIMTest</description>
  </rule>

  <rule id="100102" level="14">
    <if_sid>553</if_sid>
    <field name="file" type="pcre2">(?i)fimtest</field>
    <description>CRITICAL: File deleted from watched folder C:\FIMTest</description>
  </rule>

</group>
```

Rule IDs from 100000 upward are reserved for custom rules. Each rule fires on the matching built-in file integrity rule when the file path contains `fimtest`.

### 3. Create a Discord webhook

1. In Discord, open the channel's settings: **Edit Channel > Integrations > Webhooks > New Webhook**.
2. Name it (for example `Wazuh Alerts`) and copy the webhook URL.

Treat the URL like a password. Anyone who has it can post to your channel. Do not commit it, paste it into chats or leave it visible in screenshots.

### 4. Add the Discord integration script

Wazuh's built-in Slack integration returned HTTP 400 from Discord in this lab, so use a small custom script that posts a native Discord embed. On the server, as root:

```bash
cp /var/ossec/integrations/slack /var/ossec/integrations/custom-discord

cat > /var/ossec/integrations/custom-discord.py <<'EOF'
#!/usr/bin/env python3
import sys, json, requests

with open(sys.argv[1]) as f:
    alert = json.load(f)
hook = sys.argv[3]

rule = alert.get("rule", {})
agent = alert.get("agent", {})
sc = alert.get("syscheck", {})
level = int(rule.get("level", 0))

embed = {
    "title": rule.get("description", "Wazuh alert"),
    "description": str(alert.get("full_log", ""))[:1000],
    "color": 0xFF0000 if level >= 14 else 0xFFA500,
    "fields": [
        {"name": "Agent", "value": str(agent.get("name", "-")), "inline": True},
        {"name": "Rule", "value": f"{rule.get('id')} (level {level})", "inline": True},
        {"name": "File", "value": str(sc.get("path", "-")), "inline": False},
        {"name": "Event", "value": str(sc.get("event", "-")), "inline": True},
    ],
    "footer": {"text": str(alert.get("timestamp", ""))},
}
r = requests.post(hook, json={"embeds": [embed]}, timeout=10)
print("# Discord response:", r.status_code)
EOF

chmod 750 /var/ossec/integrations/custom-discord*
chown root:wazuh /var/ossec/integrations/custom-discord*
```

The script colors level 14 and above red and everything else orange.

### 5. Register the integration

Edit `/var/ossec/etc/ossec.conf` on the server. Add this block at the top level, just before the final `</ossec_config>` tag (not inside `<syscheck>` or any other section):

```xml
<integration>
  <name>custom-discord</name>
  <hook_url>PASTE_WEBHOOK_URL_HERE</hook_url>
  <level>12</level>
  <alert_format>json</alert_format>
</integration>
```

Notes:

- The name must start with `custom-` and match the script file name.
- Use the webhook URL exactly as Discord gives it. Do not add `/slack` to the end, which is only for Discord's Slack-compatible endpoint.
- `<level>12</level>` is a minimum, so it sends every alert at level 12 or higher, covering both high (12 to 14) and critical (15) severity. To send only specific rules, replace `<level>` with `<rule_id>100100,100101,100102</rule_id>`.

### 6. Validate and restart

```bash
/var/ossec/bin/wazuh-analysisd -t
systemctl restart wazuh-manager
```

The first command prints nothing when the configuration is valid. Wait a minute or two for the manager and agent to reconnect.

## Test it

On the Windows PC (PowerShell as Administrator):

```powershell
echo "hello" > C:\FIMTest\alert.txt
Start-Sleep 5
echo "changed" >> C:\FIMTest\alert.txt
Start-Sleep 5
del C:\FIMTest\alert.txt
```

### Expected result

- **Dashboard:** open **Threat Hunting > Events**, select the agent, set the time range to the last hour and search `rule.id: 100100 or rule.id: 100101 or rule.id: 100102`. Three alerts appear at levels 12, 12 and 14.
- **Discord:** three messages arrive within seconds. The modified event shows the old and new MD5, SHA1 and SHA256 hashes and the size change. The deleted event is red.
- **Overview:** the High severity counter (levels 12 to 14) rises by three.

To test the Discord script by itself without waiting for a real alert:

```bash
printf '%s\n' '{"timestamp":"2026-01-01T00:00:00.000+0000","rule":{"level":12,"description":"TEST alert","id":"100100"},"agent":{"id":"001","name":"test"},"id":"1","location":"test"}' > /tmp/test.alert
read -s "?Webhook URL: " HOOK    # zsh; in bash use: read -s -p "Webhook URL: " HOOK
/var/ossec/integrations/custom-discord /tmp/test.alert "" "$HOOK" debug
```

A `# Discord response: 204` line and a message in the channel mean the script and webhook work.

## Troubleshooting

| Symptom | Likely cause | What to check |
| --- | --- | --- |
| No alerts in the dashboard | The agent is not watching the folder or was not restarted | Confirm the `<directories>` line sits inside `<syscheck>`, restart the agent, and look for the folder in the agent's `ossec.log` |
| Dashboard alerts appear but Discord is silent | Integration block missing, misplaced or using a stale webhook | Check the block is top-level and the URL is current, run `wazuh-analysisd -t`, and confirm `wazuh-integratord` is running with `ps aux \| grep integratord` |
| Discord returns 400 | Using the built-in Slack integration against Discord | Use the `custom-discord` script from step 4 |
| Discord returns 404 | The webhook was deleted or the URL is wrong | Create a new webhook and update `ossec.conf` |
| Custom rule does not fire | Path regex does not match | Open an alert's Document Details and check `syscheck.path`, then adjust the regex |
| Dashboard search returns nothing | Time range is fixed to an old window | Reset it to Last 1 hour and press Refresh |
| Dashboard shows a 500 right after a restart | The manager's API is still starting | Wait a few minutes, then hard refresh |
| Dashboard restarts in a loop, Port 443 in use | A leftover dashboard process holds the port | Stop the service, kill the old process, check the port is free, start once |

`/var/ossec/logs/integrations.log` records each integration run, but it also contains the webhook URL on every line. Do not paste it anywhere without removing the URL.

## Security notes

- Keep the webhook URL out of version control, chat messages and screenshots. If it leaks, delete the webhook in Discord and create a new one.
- Rotate the Wazuh default and installer passwords after setup, and keep `wazuh-install-files.tar` private because it contains every generated password.
- If you enabled `logall` or `logall_json` while debugging, turn them off again so the archives do not fill the disk.
- Keep `C:\FIMTest` as a disposable test folder only. For real monitoring, choose specific directories and tune the rule levels so the channel does not become noisy.

## Cleanup

```powershell
Remove-Item -Recurse -Force C:\FIMTest        # Windows, when finished testing
```

```bash
rm -f /tmp/test.alert /tmp/real.alert          # Wazuh server
```

Remove the `<directories>` line from the agent config and the `<integration>` block from the server config if you no longer want the monitoring and notifications.

## Next steps

- Detect repeated failed Windows logins (event 4625) with a frequency-based custom rule.
- Add active response to block an offending IP.
- Add an email or Google Chat notification as a second channel.
- Adapt the same pipeline for a cloud-hosted Wazuh server and company endpoints.
