# DogDoor
Lets the BloodHound back in.

The purpose of this script is to modify ACLs for both NetSessionEnum and SAMR API calls so that a non-privileged user can enumerate this information. This will allow an organization's blue team use BloodHound to gather information necessary for attack path generation without exposing the same information to a malicious attacker.

This is written to be simple PowerShell, and commented so it can be understood quickly by the team implementing it on a network. 

There are four functions defined:

Invoke-DogDoor - This is a meta-function that resolves a Username to a SID and then calls add-NetSessionEnumACL and Add-SAMRACL with that SID. 

Add-NesSessionEnumACL - Appends to the NetSessionEnum ACL Registry key to allow the specified SID

Add-SAMRACL - Appends to the RestrictRemoteSam ACL to allow the specified SID. It creates a new key with a default ACL if one is not found. 

Get-CurrentACLs - Lists the current ACLs applied to both NetSessionEnum and SAMR
