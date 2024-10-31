## Integration of Azure Woodle and M365 Woodle on Wazuh

With the integration of **Azure Woodle** and **M365 Woodle**, which are modular structures on Wazuh, a custom script, rule, and decoder were created to address the **"conflict"** issue in Filebeat fields.

### Automation with Cron Job

A cron job was set up for the script named `SignIns.py` to run every minute:

```bash
*/1 * * * * /usr/bin/python3 /var/ossec/integrations/SignIns.py
