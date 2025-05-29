# ADDynamicMembership
**ADDynamicMembership** is a PowerShell script that dynamically manages membership of Active Directory Organizational Units (OUs) or groups based on user-defined rules. These rules are written as PowerShell-style filters and stored in a specified attribute of the target containers.

Because objects in Active Directory can belong to only one OU, the script ensures that objects which no longer match a destination OU’s filter are moved back to their appropriate default containers, depending on their object class:
- Users -> ```CN=Users,DC=...```
- Groups -> ```CN=Users,DC=...```
- Computers -> ```CN=Computers,DC=...```
- OUs -> Not moved

> 💡 Tip: Schedule this script to run periodically (e.g., every 5 minutes) for near real-time updates and dynamic membership management.

## 🔍 Filter syntax
Filters must follow this structure:
```powershell
<property> <operator> '<value>'
```
- **Property**: The AD attribute to evaluate (e.g., ```DisplayName```, ```objectClass```, ```distinguishedName```)
- **Operator**: A valid PowerShell comparison operator (e.g., ```-eq```, ```-like```)
[Learn more about PowerShell comparison operators](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_comparison_operators)
- **Value**: The comparison value, always enclosed in single quotes (```'value'```)

#### Important Notes:
- Do **not** wrap the entire filter in double quotes.
- Filters can be combined using logical operators like ```-and``` and ```-or```.

### 🧪 Examples
- Match objects where the name starts with ```john```:
```PowerShell
name -like 'john*'
```

- Match computers currently in the Sales OU:
```PowerShell
objectClass -eq 'computer' -and distinguishedName -like '*OU=Sales,DC=Contoso,DC=Com'
```

## ⚙️ Parameters
| Parameter       | Description                                                       |
| --------------- | ----------------------------------------------------------------- |
| `-Attribute`    | The name of the AD attribute that contains the membership filter (default is ```extensionName```). |
| `-LogPath`      | Path where the main script log file will be saved.                |
| `-CsvLogPath`   | Path to save the CSV-formatted detailed log.                      |
| `-CsvDelimiter` | Delimiter used in the CSV file (default is comma `,`).            |



## 📝 Logging
The script generates two types of log files:
- ```.log``` file: Contains a summary of the script’s execution, including actions and any errors.
- ```.csv``` file: A detailed table of every membership change applied during the run.

> By default, logs are saved to:
> ```C:\Windows\Temp\AdDynamicMembership```
> Logs are automatically rotated daily.


## 📦 Installation
1. Download the latest version of the script from this Github repository.
2. Run it manually in PowerShell or create a scheduled task to run it at regular intervals.


## 🚀 Example usage
### Move computers from default continer
Let’s say you want to move computers named ```SALES-PCXX``` from the default ```Computers``` container to the **Sales OU**.

1. Go to the **Sales OU** and set the membership filter in the ```extensionName``` attribute (or the attribute you defined via ```-Attribute``` parameter):
```PowerShell
distinguishedName -like 'CN=SALES-PC*,CN=Computers,DC=contoso,DC=com'
```

2. Run the script:
```PowerShell
.\ADDynamicMembership.ps1
```

## 🛠️ Best Practices
- Use meaningful and specific filters to avoid misclassification of AD objects.
- Always test your filters in a non-production environment.
- Schedule regular script execution using Task Scheduler or another automation tool for continuous synchronization.