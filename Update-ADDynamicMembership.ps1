<#
.SYNOPSIS
    Dynamically manages AD object membership in OUs or groups based on custom attribute filters.
.DESCRIPTION
    This script dynamically manages membership of Active Directory Organizational Units (OUs) and groups
    based on user-defined rules. These rules are written as PowerShell-style filters and stored in a
    specified attribute of the target containers.

    Because objects in Active Directory can belong to only one OU, the script ensures that objects which
    no longer match a destination OU’s filter are moved back to their appropriate default containers,
    depending on their object class:
        - Users: move to CN=Users,DC=...
        - Groups: move to CN=Users,DC=...
        - Computers: move to CN=Computers,DC=...
        - OUs: do not move.

    It is highly recommended to schedule this script to run periodically (e.g. 5 minutes) for near
    real-time updates and dynamic membership management.

    FILTER SYNTAX
    =============
    Filters must follow this structure:
        <property> <operator> '<value>'
    where
        - Property is the AD attribute to evaluate (e.g., DisplayName, objectClass, distinguishedName)
        - Operator is a valid PowerShell comparison operator (e.g., -eq, -like)
        - Value is the comparison value, always enclosed in single quotes ('value').
    IMPORTANT:
        - Do **not** wrap the entire filter in double quotes.
        - Filters can be combined using logical operators like '-and' and '-or'.


    LOGGING
    =======
    The script generates two types of LOG files:
        - .log file: Contains a summary of the script’s execution, including actions and any errors.
        - .csv file: A detailed table of every membership change applied during the run.
    By default, LOGS are saved to: 'C:\Windows\Temp\AdDynamicMembership' and are automatically rotated daily.

.PARAMETER Attribute
    Set the name of the AD attribute that contains the membership filter
.PARAMETER LogPath
    Path where the main script log file will be saved.
.PARAMETER CsvLogPath
    Path to save the CSV-formatted detailed log.
.PARAMETER CsvDelimiter
    Delimiter used in the CSV file (default is comma ,).
.EXAMPLE
    Filter to match objects where the name starts with 'john':
    name -like 'john*'
.EXAMPLE
    Filter to match computers currently in the Sales OU:
    objectClass -eq 'computer' -and distinguishedname -like '*OU=Sales,DC=Contoso,DC=Com'
.INPUTS
    None
.OUTPUTS
    None
.NOTES
    Version:            2.0.0 - Modified the way how to process filters. Now the script use where-object filter system.
                        1.2.0 - Help written.
                        1.1.0 - Included OU's as dynamic containers.
                        1.0.0 - Initial release.
    Last Generated:     29 May 2025
    Developed by:       JLInF
    License:            MIT License

.LINK
    https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_comparison_operators
#>
#Requires -Modules ActiveDirectory

param(
    [Parameter(Mandatory=$false)]$Attribute="extensionName",
    [Parameter(Mandatory=$false)]$LogPath="$env:windir\Temp\AdDynamicMembership\$(Get-date -Format "yyyy-MM-dd")_Update-ADDynamicMembership.log",
    [Parameter(Mandatory=$false)]$CsvLogPath="$env:windir\Temp\AdDynamicMembership\$(Get-date -Format "yyyy-MM-dd")_Update-ADDynamicMembership.csv",
    [Parameter(Mandatory=$false)]$CsvDelimiter=","
)


# Add members to an OU
function Add-ADOUMember{
    param(
        [Parameter(Mandatory=$true)]$OrganizationalUnit,
        [Parameter(Mandatory=$true)]$Members
    )

    foreach ($member in $members){
        Move-ADObject -Identity $Member -TargetPath $OrganizationalUnit
    }
}

# Remove members from an OU. The members are moved out to the defined default OU foreach object class
function Remove-ADOUMember{
    param(
        [Parameter(Mandatory=$true)]$Members
    )

    foreach ($member in $members){
        $memberClass=$member.objectclass
        Move-ADObject -Identity $Member.DistinguishedName -TargetPath $defaultOU.$memberClass
    }
}

# Set the operation information to the Log object
function Set-LogData{
    param(
        [Parameter(Mandatory=$true)]$Objects,
        [Parameter(Mandatory=$true)][ValidateSet("Add", "Remove")]$Operation
    )

    $logdata=@()
    foreach ($object in $Objects){
        $logdata+=[pscustomobject]@{
            ContainerName=$ContainerName
            ContainerClass=$ContainerClass
            ContainerDN=$ContainerDN
            Date=(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            Operation=$Operation
            ObjectName=$object.Name
            ObjectClass=$object.Objectclass
            ObjectDN=$object.DistinguishedName
        }
    }

    return $logdata
}

# Converts filter string to Where-Object filter syntax
# "name -eq 'john'" -> {$_.name -eq 'john'}
function ConvertTo-WOFilter{
    param(
        [Parameter(Mandatory=$true)]$AttrUserString
    )

    $AttrUserString_Divided=$AttrUserString.split(" ")
    $WordsToReplace=$AttrUserString_Divided | Where-Object {$_ -notlike "'*" -and $_ -notlike "-*" -and $_ -notlike "(*" -and $_ -ne "true" -and $_ -ne "false"}
    $WordsToReplaceParenthesis=$AttrUserString_Divided| Where-Object {$_ -like "(*"}

    $WordsToReplace | ForEach-Object{
        $token=$_
        $replacement='$$_.'+$token
        $AttrUserString_Divided=$AttrUserString_Divided -replace "\b$token\b",$replacement
    }

    $WordsToReplaceParenthesis | ForEach-Object{
        $token=$_
        $replacement='($$_.'+$token.Trim("(")
        $AttrUserString_Divided=$AttrUserString_Divided -replace "\$token",$replacement
    }

    [string]$filter_string=$AttrUserString_Divided -join ' '
    $Filter=[Scriptblock]::Create($filter_string)

    $Filter
}

Start-Transcript -Path $LogPath -Append

$domainDN=(Get-ADDomain).DistinguishedName
$defaultOU=@{
    computer="CN=Computers,$domainDN"
    user="CN=Users,$domainDN"
    group="CN=Users,$domainDN"
}

$full_logdata=@()

try{
    # Get all the groups and OU's that have the defined attribute set
    $dynamic_defined_containers=Get-ADObject -LDAPFilter "(&($Attribute=*)(|(objectClass=group)(objectClass=organizationalUnit)))" -Properties $Attribute
}
catch{
    $_.exception.message
    exit
}

foreach ($dynamic_container in $dynamic_defined_containers){
    $ContainerName=$dynamic_container.Name
    $ContainerClass=$dynamic_container.ObjectClass
    $ContainerDN=$dynamic_container.DistinguishedName

    $filter=$dynamic_container.$Attribute

    # Objects that may be in the container
    $filterscript=ConvertTo-WOFilter -AttrUserString $filter
    $query_objects=Get-ADObject -Filter "objectclass -ne 'organizationalUnit'" -Properties * | Where-Object -FilterScript $filterscript

    # Dynamic Group
    if ($dynamic_container.ObjectClass -eq "group"){
        $objects_already_in=Get-ADGroupMember -Identity $ContainerDN
        $remove_command={Remove-ADGroupMember -Identity $ContainerDN -Members $objects_to_del -Confirm:$false}
        $add_command={Add-ADGroupMember -Identity $ContainerDN -Members $objects_to_add -Confirm:$false}
    }
    # Dynamic OU
    elseif ($dynamic_container.ObjectClass -eq "organizationalunit"){
        $objects_already_in=Get-ADObject -SearchBase $ContainerDN -Filter "objectclass -ne 'organizationalunit'" -Properties samaccountname
        $remove_command={Remove-ADOUMember -Members $objects_to_del}
        $add_command={Add-ADOUMember -Members $objects_to_add -OrganizationalUnit $ContainerDN}
    }

    $objects_to_del=$objects_already_in | Where-Object {$_.DistinguishedName -notin $query_objects.DistinguishedName}
    $objects_to_add=$query_objects | Where-Object {$_.DistinguishedName -notin $objects_already_in.DistinguishedName}

    if ($objects_to_del){
        try{
            $remove_command.Invoke()
            $full_logdata+=Set-LogData -Objects $objects_to_del -Operation Remove
            Write-Host "[$ContainerClass][$ContainerName] $(@($objects_to_del).count) objects removed."
        }
        catch{
            $_.exception.message
        }
    }
    else{
        Write-Host "[$ContainerClass][$ContainerName] No objects to remove."
    }


    if ($objects_to_add){
        try{
            $add_command.Invoke()
            $full_logdata+=Set-LogData -Objects $objects_to_add -Operation Add
            Write-Host "[$ContainerClass][$ContainerName] $(@($objects_to_add).count) objects added."
        }
        catch{
            $_.exception.message
        }

    }
    else{
        Write-Host "[$ContainerClass][$ContainerName] No objects to add."
    }
}

Write-Host "Review file '$CsvLogPath' for detailed information."

# Export log object to CSV
$full_logdata | Export-Csv -Path $CsvLogPath -Encoding UTF8 -NoTypeInformation -Append -Delimiter $CsvDelimiter

Stop-Transcript