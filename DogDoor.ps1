 Function Invoke-AddACLs {
    param(
        [Parameter(Mandatory = $true)][string]$User
    )
    $usertoadd = New-Object System.Security.Principal.NTAccount($User)
    $SID = $usertoadd.Translate([System.Security.Principal.SecurityIdentifier])
    Write-Host $usertoadd has a SID of $SID

    Add-NetSessionEnumACL -SID $SID
    Write-Host "--------------"
    Add-SAMRACL -SID $SID
}

Function Add-NetSessionEnumACL {
    param(
        [Parameter(Mandatory = $true)][string]$SID
    )

    Write-Host "Starting NetSessionEnum ACL"

    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity"
    $subkey = "SrvsvcSessionInfo"
    $right = 0x00000001

    #Get the current binary value from the registry
    #This one exists by default, so no real need to check if it doesn't exist
    Write-Host "Getting current ACL from $key $subkey"
    $value = Get-ItemPropertyValue -Path $key -Name $subkey

    #Convert the binary value to a RawSecurityDescriptor object
    ###$currentacl = New-Object -TypeName System.Security.AccessControl.CommonSecurityDescriptor -ArgumentList $true, $false, $value, 0
    $currentacl = New-Object -TypeName System.Security.AccessControl.RawSecurityDescriptor -ArgumentList $value, 0

    #Create a new ACE for our user defined aboveA
    #$newace = New-Object System.Security.AccessControl.CommonAce([System.Security.AccessControl.AceFlags]::None, [System.Security.AccessControl.AceQualifier]::AccessAllowed, $right, $SID, $false, $null)
    $newace = New-Object System.Security.AccessControl.CommonAce -ArgumentList None, AccessAllowed, $right, $SID, $false, $null

    #Check if the ACE already exists
    if ($currentacl.DiscretionaryAcl.GetEnumerator() -notcontains $newAce) {
        Write-Host "ACE for $SID Not Found in ACL"

        #If it doesn't exist, Add the new ACE to the ACL
        ###$currentacl.DiscretionaryAcl.AddAccess([System.Security.AccessControl.AccessControlType]::Allow, $SID, $right, 0, 0)
        $currentacl.DiscretionaryAcl.InsertAce($currentacl.DiscretionaryAcl.Count, $newace)
        Write-Host  "Adding ACE for $SID to ACL"

        #Convert the ACL back to binary
        $binaryacl = New-Object -TypeName System.Byte[] -ArgumentList $currentacl.BinaryLength
        $currentacl.GetBinaryForm($binaryacl, 0)
        Write-Host "Converted ACL to binary"

        #Write the new binary value to the registry
        try {
            Write-Host "Writing $currentacl to $key $name"
            Set-ItemProperty -Path $key -Name $subkey -Value $binaryacl
        }
        catch {
            Write-Error "Error setting registry key $key $subkey to $binaryacl"
        }
    }
    else {
        Write-Host "ACE Exists in current ACL"
    }
}

Function Add-SAMRACL {
    param(
        [Parameter(Mandatory = $true)][string]$SID
    )

    Write-Host "Starting SAMR ACL"

    $key = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $subkey = "RestrictRemoteSam"
    $right = 0x20000

    #If the RestrictRemoteSam key exists, get the current value, if not, assign an empty value
    try {
        $value = Get-ItemPropertyValue -Path $key -Name $subkey
        if ("" -eq $value) {
            Write-Host "RestrictRemoteSam value is null, creating default ACL"
            $currentacl = New-Object -TypeName System.Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAG:BAD:(A;;RC;;;BA)"
        }
        else {
            $currentacl = New-Object -TypeName System.Security.AccessControl.RawSecurityDescriptor -ArgumentList $value
            Write-Host "Getting current ACL from $key $subkey"
        }
    }
    catch {
        $value = ""
        $currentacl = New-Object -TypeName System.Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAG:BAD:(A;;RC;;;BA)"
        Write-Host "RestrictRemoteSam key not found, creating blank ACL"
    }

    #Create a new ACE for our user defined above
    #$newace = New-Object System.Security.AccessControl.CommonAce([System.Security.AccessControl.AceFlags]::None, [System.Security.AccessControl.AceQualifier]::AccessAllowed, $right, $SID, $false, $null)
    $newace = New-Object System.Security.AccessControl.CommonAce -ArgumentList None, AccessAllowed, $right, $SID, $false, $null

    if ($currentacl.DiscretionaryAcl.GetEnumerator() -notcontains $newAce) {
        Write-Host "ACE for $SID Not Found in ACL"
        #If it doesn't exist, Add the new ACE to the ACL
        $currentacl.DiscretionaryAcl.InsertAce($currentacl.DiscretionaryAcl.Count, $newace)
        Write-Host  "Adding ACE for $SID to ACL"

        #Convert the ACL to SDDL
        $sddl = $currentacl.GetSddlForm([System.Security.AccessControl.AccessControlSections]::All)

        #Write the new SDDL value to the registry
        try {
            Write-Host "Writing $currentacl to $key $name"
            Set-ItemProperty -Path $key -Name $subkey -Value $sddl
        }
        catch {
            Write-Error "Error setting registry key $key $subkey to $sddl"
        }

    }
    else {
        Write-Host "ACE for $SID exists in current ACL"
    }
}

Function Get-CurrentACLs {
    $netsessvalue = Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity" -Name "SrvsvcSessionInfo"
    $netsessacl = New-Object -TypeName System.Security.AccessControl.RawSecurityDescriptor -ArgumentList $netsessvalue, 0

    Write-Host "Current ACL for NetSessionEnum"
    $netsessacl.DiscretionaryAcl | Select-Object -Property SecurityIdentifier, AccessMask, AceType | Format-Table

    Write-Host "---------------------"

   try {
        $samrvalue = Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictRemoteSam"
        $samracl = New-Object -TypeName System.Security.AccessControl.RawSecurityDescriptor -ArgumentList $samrvalue
       
        Write-Host "Current ACL for SAMR"
        $samracl.DiscretionaryAcl | Select-Object -Property SecurityIdentifier, AccessMask, AceType | Format-Table 
    }
    catch {
        Write-Host "No ACLs for RestrictRemoteSam found"
    }
}

#If this is ran via GPO, uncomment the below line and replace DOMAIN\USER with the user you want to add to the ACLs
#Invoke-AddACLs -User DOMAIN\USER
