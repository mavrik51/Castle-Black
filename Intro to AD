What is Active Directory?

Active Directory (AD), introduced in 1999 as part of Windows Server 2000, AD is responsible for authenticating and authorizing all users and computers in a windows domain network. It stores info about all the objects such as Users, Computers, Groups and etc. Remember! it is holding all the keys to the kingdom. Obviously, those juicy information are what we are after.

Knowing the castle is the key!
If we are scheming an attack on one the most secured services of Microsoft, we need to be prepared. Precision is an inseparable element of a successful Penetration Tester. There are technically 7 different types of Active Directory. Each of them are deployed in different way, places and for different purposes.


Local Active Directory (AD)
Purpose:
Centralized administration for servers, workstations, users, and applications

Deployment:
Windows Server OS Family
Active Directory Domain Controllers

Limitations:
Requires direct network connection
Reliance on customer managed networking: DNS, VPN, and Servers (Physical and Virtual)

Azure Active Directory (AAD)
Purpose:
Centralized administration for cloud services
Hybrid scenarios supported via Azure AD Connect connecting to local Active Directory
Use your corporate credentials/passwords

Deployment:
Cloud Service

Limitations:
Lack of IT protection without AAD P1 and P2 licensing
Device bases security requires EM+S licensing for Intune

Azure Active Directory Domain Services (AADDS)
Purpose:
Local Active Directory (Fully compatible with Windows Server Active Directory)
Lift and Shift scenarios for Windows servers
Use your corporate credentials/passwords
NTLM and Kerberos authentication
Co-mingle local Active Directory users and Azure Active Directory users

Deployment:
Cloud Service (Two domain controllers are available by IP only)
Highly available domain
Auto-remediation
Automatic backups

Limitations:
Organizational Units are flat and not brought over from local AD/AAD
Not recommended for workstations
Administrators are NOT Domain Admins (it’s also a good thing)
==============================================================
Now that we know about some of the most commonly deployed Active Directory topologies lets start.
==================================================================================================

Rise of the PowerShell
=======================
Bypass PowerShell to run Scripts with privilege :

- env:ExecutionPolicypreference ="bypass"
- env:ExecutionPolicypreferehce
- Set-ExecutionPolicy bypass -Force

Note: You can do almost anything with Powershell in a Windows and an Active Directory environment, get used to it. Remember, The best way to stay under the radar is to use the method of LOTL (Leave off the land) in a target machine.

Preparing the Domain: ( LAB SETUP)
==================================
OS: Windows Server 2019/2016/2012

I'm escaping the Windows installation part, Just mount your ISO file and power on your VM and be done with it.



Domain Name : castleblack.com
==============================
- Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

- Import-Module ADDSDeployment

- Install-ADDSForest -CreateDnsDelegation:$false -DatabasePath 'C:\Windows\NTDS' -DomainMode 'Win2012' -DomainName 'castleblack.com' -DomainNetbiosName 'castleblack' -ForestMode 'Win2012' -InstallDns:$true -LogPath 'C:\Windows\NTDS' -NoRebootOnCompletion:$true -SysvolPath 'C:\Windows\SYSVOL' -SafeModeAdministratorPassword (Convertto-SecureString -AsPlainText "V3rsprich@1415" -Force) -Force:$true


Domain Prep with JSON and PS :
==============================
Make sure to save these two in separate files and into the same folder on your Domain Controller. 

Note:

Using PowerShell and custom templates to create new users | 4sysops

dcprep.ps1 content
===================

if(Test-Path .\dcprep.json)
{
    $config = cat .\dcprep.json | convertfrom-json
    if($config)
    {
        Import-Module ActiveDirectory 


        $DomainRoot = (Get-ADDomain).distinguishedname
        $DNSRoot = (get-addomain).DNSRoot


        foreach($ou in $config.ou)
        {
            if($ou.DistinguishedName)
            {
                $oupath = $ou.DistinguishedName + ","+ $DomainRoot
            }
            else
            {
                $oupath = $DomainRoot
            }
            New-ADOrganizationalUnit -Name $ou.name -Path $oupath
        }


        foreach($user in $config.user)
        {
            $upn = $user.UserPrincipalName + "@" + $DNSRoot
            $securePassword = ConvertTo-SecureString $user.Password -AsPlainText -force
            New-ADUser -Name $user.name -SamAccountName $user.samAccountName -DisplayName $user.DisplayName -UserPrincipalName $upn -AccountPassword $securePassword -Enabled $true -Path ($user.OU + "," + $DomainRoot) -PasswordNeverExpires $true
        }


        foreach($group in $config.GroupAdd)
        {
            if($group.ou)
            {
                $oupath = $group.ou + ","+ $DomainRoot
            }
            else
            {
                $oupath = $DomainRoot
            }
            New-ADGroup -Name $group.Name -GroupScope $group.scope -GroupCategory $group.category -Description $group.description -Path $oupath
        }


        foreach($group in $config.GroupMember)
        {
            Add-ADGroupMember -Identity $group.group -Members $group.member
        }

    }
}



dcprep.json content
====================

{
    "ou": [
      {
          "Name":  "company",
          "DistinguishedName":  ""
      },
      {
          "Name":  "User",
          "DistinguishedName":  "OU=company"
      },
      {
          "Name":  "Computer",
          "DistinguishedName":  "OU=company"
      },
      {
          "Name":  "Groups",
          "DistinguishedName":  "OU=company"
      },
      {
          "Name":  "DomainUser",
          "DistinguishedName":  "OU=User,OU=company"
      },
      {
          "Name":  "ServiceAccounts",
          "DistinguishedName":  "OU=User,OU=company"
      },
      {
          "Name":  "Admins",
          "DistinguishedName":  "OU=User,OU=company"
    }


  ],
   "user": [
      {
          "UserPrincipalName":  "jamie",
          "SamAccountName":  "jamie",
          "Name":  "jamie",
          "OU":  "OU=DomainUser,OU=User,OU=company",
          "DisplayName":  "Jamie lannister",
          "Password":  "Cersi@2021"
      },
      {
          "UserPrincipalName":  "cersi",
          "SamAccountName":  "cersi",
          "Name":  "cersi",
          "OU":  "OU=ServiceAccounts,OU=User,OU=company",
          "DisplayName":  "cersei lannister",
          "Password":  "Jamie@2021"
      },
      {
          "UserPrincipalName":  "tyrion",
          "SamAccountName":  "tyrion",
          "Name":  "tyrion",
          "OU":  "OU=Admins,OU=User,OU=company",
          "DisplayName":  "tyrion lannister",
          "Password":  "Goldlov3r@2021"
      }
  ],
  "GroupAdd" : [
      {
          "Name": "Queens",
          "Scope": "Global",
          "Category": "Security",
          "Description": "Queens",
          "OU":"OU=Groups,OU=company"
      },
      {
        "Name": "Kings",
        "Scope": "Global",
        "Category": "Security",
        "Description": "Kings",
        "OU":"OU=Groups,OU=company"
      },
      {
          "Name": "Knight",
          "Scope": "Global",
          "Category": "Security",
          "Description": "Knight",
          "OU":"OU=Groups,OU=company"
      }
  ],
  "GroupMember" : [
      {
          "Group": "Queens",
          "Member": "cersi"
      },
      {
        "Group": "Kings",
        "Member": "tyrion"
    },
    {
        "Group": "Knight",
        "Member": "jamie"
    }
  ]


  }
  
============================ 
execute dcprep.ps1
End of part One.
In the Next Episode: RECON.
