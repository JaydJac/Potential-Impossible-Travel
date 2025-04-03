# Potential-Impossible-Travel

# Detecting Impossible Travel Logins in Microsoft Sentinel  

## Explanation  

Many organizations enforce policies restricting logins to specific geographic regions, prohibiting account sharing, and preventing the use of non-corporate VPNs. In this lab, I configured an **impossible travel detection alert** to identify erratic login patterns—specifically when a user logs in from multiple geographic regions within a short time frame.  

Whenever a user logs into **Azure** or authenticates with their main account, logs are recorded in the **SigninLogs** table. These logs are forwarded to **Microsoft Sentinel** via the **Log Analytics Workspace**, enabling security monitoring.  

To detect potential **impossible travel scenarios**, I configured an alert to trigger whenever a user logs in from more than one location **within a 7-day period**. Not all triggers will be true positives, but this approach allows me to investigate unusual authentication patterns.  

To generate logs for testing, I:  
- Created a new **Virtual Machine (VM)** (if one wasn’t already available).  
- Logged into the VM.  
- Accessed **Azure** via [portal.azure.com](https://portal.azure.com) from within the VM.  

This process generated a logon event from a random city on the East Coast (East US 2 region), simulating an impossible travel scenario.  

---

## Part 1: Creating an Alert Rule (Potential Impossible Travel)  

I designed a **Sentinel Scheduled Query Rule** to detect when a user logs into multiple geographic regions within a set timeframe. The alert triggers if a user logs into **two or more different regions within a 7-day period**.  

### **KQL Query**  

```kusto
// Locate Instances of Potential Impossible Travel  
let TimePeriodThreshold = timespan(7d); // Define lookback period  
let NumberOfDifferentLocationsAllowed = 2;  
SigninLogs  
| where TimeGenerated > ago(TimePeriodThreshold)  
| summarize Count = count() by UserPrincipalName, UserId,  
  City = tostring(parse_json(LocationDetails).city),  
  State = tostring(parse_json(LocationDetails).state),  
  Country = tostring(parse_json(LocationDetails).countryOrRegion)  
| project UserPrincipalName, UserId, City, State, Country  
| summarize PotentialImpossibleTravelInstances = count() by UserPrincipalName, UserId  
| where PotentialImpossibleTravelInstances > NumberOfDifferentLocationsAllowed
```
## Alert Rule Configuration
Once my query was validated, I created a **Scheduled Query Rule** in **Sentinel → Analytics → Schedule Query Rule** with the following settings:

- ✅ **Enabled the Rule**  
- 🔹 **Mapped MITRE ATT&CK Framework Categories**  
- ⏳ **Ran the query every 4 hours**  
- 📊 **Looked back at the last 5 hours of data**  
- 🚨 **Stopped the rule from running after an alert was generated**  
- 🔄 **Configured Entity Mappings**:  
  - **Account**
    - **Identifier:** `AadUserId`, **Value:** `UserId`  
    - **Identifier:** `DisplayName`, **Value:** `UserPrincipalName`  
- 🔔 **Automatically created an Incident when the rule was triggered**  
- 🗂 **Grouped all alerts into a single Incident per 24-hour period**  

---

## Part 2: Triggering an Alert and Creating an Incident  
To verify the alert, I simulated a login from different locations using my **VM**. When the alert triggered, an **incident was automatically created** in Sentinel.

⚠ **Reminder:** I ensured I was navigating correctly between **[Configuration → Analytics]** and **[Threat Management → Incidents]** sections to manage the incident properly.

---

## Part 3: Investigating the Incident  
Following the **NIST 800-161: Incident Response Lifecycle**, I worked through the incident to resolution.

### **1. Preparation**
- 📝 Documented roles, responsibilities, and procedures.  
- 🛠 Ensured tools, systems, and training were in place for incident handling.  

### **2. Detection and Analysis**  
- 🔍 Identified and validated the incident.  
- 👤 Assigned the incident to myself and set the status to **Active**.  
- 🕵️ Used **Sentinel’s Investigation tools** to analyze the incident.  
- 📂 Checked the `SigninLogs` table to determine if the login pattern was legitimate or a potential compromise.  

#### **KQL Query for Further Investigation**  
```kusto
let TimePeriodThreshold = timespan(7d);  
SigninLogs  
| where TimeGenerated > ago(TimePeriodThreshold)  
| where UserPrincipalName == TargetUserPrincipalName  
| project TimeGenerated, UserPrincipalName,  
  City = tostring(parse_json(LocationDetails).city),  
  State = tostring(parse_json(LocationDetails).state),  
  Country = tostring(parse_json(LocationDetails).countryOrRegion)  
| order by TimeGenerated desc
```
## Observed Logon Patterns & Notes

| User | Location 1 | Location 2 | Timeframe | Status |
|------|------------|------------|-----------|--------|
| `josh.madakor@gmail.com` | Everson, WA | Seattle, WA | 30 minutes | ✅ Normal |
| `9e64658ec855cd90169a726d167fa6ec30a9940a8ec0ccaf14f736f11c3e8847@lognpacific.com` | Miami, FL | Pompano Beach, FL | 30 minutes | ✅ Normal |

---

## 3. Containment, Eradication & Recovery

🔒 **It was determined that the alert was a TRUE Benign.**  
- User `josh.madakor@gmail.com` logged into **Everson and Seattle, Washington** within a reasonable amount of time. This behavior is normal.  
- User `9e64658ec855cd90169a726d167fa6ec30a9940a8ec0ccaf14f736f11c3e8847@lognpacific.com` logged into **Miami, Florida and Pompano Beach, Florida** within a reasonable amount of time. This behavior is normal.

### **Conclusion: Both accounts will remain enabled due to expected behavior.**

---

## 4. Post-Incident Activities

🔐 **Explored the option of implementing geofencing** to prevent logins from outside the country.  

📑 **Updated internal policies** and security controls to prevent future occurrences.  
🏛 **Recommended enforcing secure access policies** using **Azure Conditional Access**.  
🗂 **Documented all findings and lessons learned**.  

---

## 5. Closure

✅ **Reviewed and confirmed the incident was fully resolved.**  
📝 **Ensured all findings and actions were properly documented** within Sentinel.  
🚪 **Closed the case**, categorizing it as:    
- ❌ **False Positive** *(Normal behavior, no further action needed)*  

---

## **Conclusion**

By leveraging **Microsoft Sentinel**, I successfully detected potential impossible travel logins, investigated the alerts, and applied best practices for incident response.

This process helped me gain insights into:  
✔ **Log analysis**  
✔ **Security monitoring**  
✔ **Incident management within Azure Sentinel**  

🚀 **This experience strengthened my ability to handle security threats in cloud environments!**  
