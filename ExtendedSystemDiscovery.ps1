
param([string]$SiteServer, [string]$SiteCode,  [string]$InstanceName )

#PowerShell { Import-Module -Global ActiveDirectory -Force }
Import-Module -Global "ActiveDirectory" -Force 


Function Get-ComputerFromAD() {
[CmdletBinding()]   
PARAM 
(   [Parameter(Position=1)] $DCServer,
    [Parameter(Position=2)] $ComputerName ) 

    $ThisComputer = @()
    $ThisComputer =  Get-ADComputer -LDAPFilter "(name=$ComputerName)"   -Server $DCServer -ErrorAction SilentlyContinue
        
    Return $ThisComputer
}

# Fill the objSMSSites array from the CAS WMI
Function Get-SMSSites() {
[CmdletBinding()]   
PARAM 
(   [Parameter(Position=1)] $CASSiteServer,
    [Parameter(Position=2)] $CASSiteCode )   
    
    Log-Append -strLogFileName $LogFileName -strLogText ("Identifying Primary Sites")
    $objSMSSites = Get-WmiObject -ComputerName $CASSiteServer -Namespace ("root\sms\Site_"+$CASSiteCode) -Query "SELECT * FROM SMS_SITE Order By SiteCode"
    Return $objSMSSites
}

# Get the site server given a specific site code
Function Get-SiteServerName() {
[CmdletBinding()]   
PARAM 
(   [Parameter(Position=1)] $SiteCode,
    [Parameter(Position=2)] $objSitesList  )   
    
    ForEach ($Site in $objSitesList ) {
        If ( $Site.SiteCode -eq $CASSiteCode ) { return $Site.ServerName }
    }
    Return $CASSiteServer 
}


# Fill the objDomains array with SQL table data from SCCM_EXT 
Function Get-ADDomains() {
[CmdletBinding()]   
PARAM 
(   [Parameter(Position=1)] $LoggingSQLServer,
    [Parameter(Position=2)] $ExtDiscDBName,
    [Parameter(Position=3)] $DomainsTableName
)   

    Log-Append -strLogFileName $LogFileName -strLogText ("Identifying searchable domains")
    $objADDomains = @()
    $SqlConnection = New-Object System.Data.SqlClient.SqlConnection
    $SqlConnection.ConnectionString = "Server=$LoggingSQLServer;Database=$ExtDiscDBName;Integrated Security=True"
    $SqlCmd = New-Object System.Data.SqlClient.SqlCommand
    $SqlCmd.CommandText = "select * from $DomainsTableName"
    $SqlCmd.Connection = $SqlConnection
    $SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
    $SqlAdapter.SelectCommand = $SqlCmd
    $objADDomains = New-Object System.Data.Datatable
    $NumRows = $SqlAdapter.Fill($objADDomains)
    $SqlConnection.Close()
    Return $objADDomains
}


Function Create-DDR() {
[CmdletBinding()]   
PARAM 
(   [Parameter(Position=1)] $SiteCode,
    [Parameter(Position=2)] $ResourceID,
    [Parameter(Position=3)] $NetBiosName,   
    [Parameter(Position=4)] $SMSUniqueIdentifier,
    [Parameter(Position=5)] $DistinguishedName,
    [Parameter(Position=6)] $Category,
    [Parameter(Position=7)] $Type,
    [Parameter(Position=7)] $DefaultDDRSiteCode    )  
        
    If ( !$SiteCode ) { $SiteCode = $DefaultDDRSiteCode }

    $SMSDisc.DDRNew("System","SA_EXT_Disc",$SiteCode) 
    IF ($SMSUniqueIdentifier)  { $SMSDisc.DDRAddString("SMS Unique Identifier",           $SMSUniqueIdentifier, 64,  $ADDPROP_KEY )  }
    IF ($NetBiosName)          { $SMSDisc.DDRAddString("Netbios Name",                    $NetBiosName,         16,  $ADDPROP_NONE)  }
    IF ($Category)             { $SMSDisc.DDRAddString("companyAttributeMachineCategory", $Category,            32,  $ADDPROP_NONE)  } 
    IF ($Type)                 { $SMSDisc.DDRAddString("companyAttributeMachineType",     $Type,                32,  $ADDPROP_NONE)  }
    If ($DistinguishedName)    { $SMSDisc.DDRAddString("Distinguished Name",              $DistinguishedName,   256, $ADDPROP_NONE)  }

    $Result = $SMSDisc.DDRWrite($DDRTempFolder+$SiteCode+"-"+$NetBiosName+"-"+$SMSUniqueIdentifier+".DDR")
    $TestFile = Get-Item -LiteralPath  ($DDRTempFolder+$SiteCode+"-"+$NetBiosName+"-"+$SMSUniqueIdentifier+".DDR") -ErrorAction SilentlyContinue
    If ($TestFile) { 
        Log-Append -strLogFileName $LogFileName  -strLogText ("Created DDR "+$DDRTempFolder+$SiteCode+"-"+$NetBiosName+"-"+$SMSUniqueIdentifier+".DDR")
        Return "Success" 
    }
    ELSE {
        Log-Append -strLogFileName $LogFileName  -strLogText ("Failed to create DDR "+$DDRTempFolder+$SiteCode+"-"+$NetBiosName+"-"+$SMSUniqueIdentifier+".DDR")
        Return "Failed" 
    }
}

# Connect to the SCCM CAS to identify all systems missing their distinguishedName, category or type 
Function Get-ClientsNoDN() {
[CmdletBinding()]   
PARAM 
(   [Parameter(Position=1)] $CASSQLServer,
    [Parameter(Position=2)] $SCCMDBName )    

        $objSCCMClients = @()
        $SqlConnection = New-Object System.Data.SqlClient.SqlConnection
        $SqlConnection.ConnectionString = "Server=$CASSQLServer;Database=$SCCMDBName;Integrated Security=True"
        $SqlCmd = New-Object System.Data.SqlClient.SqlCommand
        $SqlCmd.CommandText = "SELECT TOP (100) PERCENT dbo.v_RA_System_SMSAssignedSites.SMS_Assigned_Sites0, dbo.v_R_System.ResourceID,  
                dbo.v_R_System.companyAttributeMachineCa0, dbo.v_R_System.companyAttributeMachineTy0, dbo.v_R_System.Distinguished_Name0, 
                dbo.v_R_System.Full_Domain_Name0,dbo.v_R_System.Netbios_Name0, dbo.v_R_System.Resource_Domain_OR_Workgr0, dbo.v_R_System.SMS_Unique_Identifier0
                FROM dbo.v_R_System LEFT OUTER JOIN dbo.v_RA_System_SMSAssignedSites ON dbo.v_R_System.ResourceID = dbo.v_RA_System_SMSAssignedSites.ResourceID
                WHERE (dbo.v_R_System.Distinguished_Name0 IS NULL OR dbo.v_R_System.Distinguished_Name0 = '') AND (dbo.v_R_System.Netbios_Name0 <> 'Unknown') Order By dbo.v_R_System.ResourceID DESC "
        $SqlCmd.Connection = $SqlConnection
        $SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
        $SqlAdapter.SelectCommand = $SqlCmd
        $objSCCMClients = New-Object System.Data.Datatable
        $NumRows = $SqlAdapter.Fill($objSCCMClients)
        $SqlConnection.Close()
        Log-Append -strLogFileName $LogFileName -strLogText ("Identified "+$NumRows+" clients with missing discovery data")
        ForEach ( $Found in $objSCCMClients ) {
            Log-Append -strLogFileName $LogFileName -strLogText ($Found.Netbios_Name0)
        }
        return $objSCCMClients
}


Function Log-Append () {
[CmdletBinding()]   
PARAM 
(   [Parameter(Position=1)] $strLogFileName,
    [Parameter(Position=2)] $strLogText )
    
    $strLogText = ($(get-date).tostring()+" ; "+$strLogText.ToString()) 
    Out-File -InputObject $strLogText -FilePath $strLogFileName -Append -NoClobber
}

Function Log-SQLDDRChange() {
PARAM 
(   [Parameter(Position=1)] $LoggingSQLServer,
    [Parameter(Position=2)] $ExtDiscDBName, 
    [Parameter(Position=3)] $LoggingTableName, 
    [Parameter(Position=4)] $ComputerName,
    [Parameter(Position=5)] $AD_DN,
    [Parameter(Position=6)] $AD_Category,
    [Parameter(Position=7)] $AD_Type,
    [Parameter(Position=12)] $SCCM_DN,
    [Parameter(Position=13)] $SCCM_Category,
    [Parameter(Position=14)] $SCCM_Type,
    [Parameter(Position=15)] $SCCM_SiteCode)

    If (!$SQLConnection) {
        $SQLConnection =  New-Object System.Data.SqlClient.SqlConnection  
        $SQLConnection.ConnectionString = "Server=$LoggingSQLServer;Database=$ExtDiscDBName;Integrated Security=True"
        $SQLConnection.Open()
    }
    $cmd = $SQLConnection.CreateCommand()
    $cmd.CommandText ="INSERT INTO $LoggingTableName  (ComputerName,AD_DN,AD_Category,AD_Type,SCCM_DN,SCCM_Category,SCCM_Type,SCCM_SiteCode) 
                        VALUES( '$ComputerName','$AD_DN','$AD_Category','$AD_Type','$SCCM_DN','$SCCM_Category','$SCCM_Type','$SCCM_SiteCode' );"
    $Result = $cmd.ExecuteNonQuery()
    $Result = $SQLConnection.Close
}

##############################
#  MAIN
#############################

#Define constants.
$ADDPROP_NONE       = 0x0
$ADDPROP_GUID       = 0x2
$ADDPROP_KEY        = 0x8
$ADDPROP_ARRAY      = 0x10

# Set parameter defaults
$PassedParams =  (" -SiteServer "+$SiteServer+" -SiteCode "+$SiteCode+" -SQLServer "+$SQLServer+" -InstanceName "+$InstanceName)
If (!$SiteServer)   { $SiteServer   = "GISSSCCMDEV2"              }
If (!$SiteCode)     { $SiteCode     = "T00"                       }
If (!$InstanceName) { $InstanceName = "ExtendedSystemDiscovery-DEV"  }

# Lookup the SCCM site definition to populate global variables
$objSiteDefinition = Get-WmiObject -ComputerName $SiteServer -Namespace ("root\sms\Site_"+$SiteCode) -Query ("SELECT * FROM sms_sci_sitedefinition WHERE SiteCode = '"+$SiteCode+"'")
$SCCMDBName = $objSiteDefinition.SQLDatabaseName
$SQLServer = $objSiteDefinition.SQLServerName
$CASSiteServer      = $SiteServer
$CASSiteCode        = $SiteCode
$DefaultDDRSiteCode = $SiteCode # used for clients with no assigned site code

#Define Variables
$ScriptPath         = $PSScriptRoot
$DDRTargetFolder    = "\D$\SCCMServer\inboxes\auth\ddm.box\"   #must include trailing \
$DDRTempFolder      = ($ScriptPath+"\TempDDRs\")
$LoggingFolder      = ($ScriptPath+"\Logs\")
$LoggingSQLServer   = $SQLServer
$ExtDiscDBName      = "SCCM_EXT"
$DomainsTableName   = "tbl_ExtDiscDomains"
$LoggingTableName   = "tbl_ExtDiscLogging"
$TodaysDate = Get-Date 

# Start logging
$LogFileName = ($LoggingFolder+$InstanceName+"-"+$TodaysDate.Year+$TodaysDate.Month.ToString().PadLeft(2,"0")+$TodaysDate.Day.ToString().PadLeft(2,"0")+".log")
Log-Append -strLogFileName $LogFileName -strLogText ("Script started")
Log-Append -strLogFileName $LogFileName -strLogText ("Creating an instance of the com object SMSResGen.SMSResGen.1" )


# Verify write folder paths exist, if not create them
If (!(Test-Path $DDRTempFolder))  { $Result = New-Item $DDRTempFolder -type directory }
If (!(Test-Path $LoggingFolder))  { $Result = New-Item $LoggingFolder -type directory }


$objSMSSites = @()
$objADDomains = @()
$objADComputers = @()
$objClientsNoDN = @()
$objDDRUpdates = @()
$objMisingDiscoveryData = @()
$objLogging = @()
   
#Load the SCCM SDK DLL
Log-Append -strLogFileName $LogFileName -strLogText ("Creating an instance of the com object SMSResGen.SMSResGen.1" )
$SMSDisc = New-Object -ComObject "SMSResGen.SMSResGen.1" 
If (!$SMSDisc) {
    Try { 
        &regsvr32 /s ($ScriptPath+"\SCCMSDKDLLs\OldDLLs\smsrsgen.dll") 
        &regsvr32 /s ($ScriptPath+"\SCCMSDKDLLs\OldDLLs\smsrsgenctl.dll") 
        $SMSDisc = New-Object -ComObject "SMSResGen.SMSResGen.1" }
    Catch { 
        Try {
            &regsvr32 /s ($ScriptPath+"\SCCMSDKDLLs\NewDLLs\smsrsgen.dll") 
            &regsvr32 /s ($ScriptPath+"\SCCMSDKDLLs\NewDLLs\smsrsgenctl.dll") 
            $SMSDisc = New-Object -ComObject "SMSResGen.SMSResGen.1" 
        }
        Catch { Log-Append -strLogFileName $LogFileName -strLogText "Failed to load COM object SMSResGen.SMSResGen.1" }
    }
}


    $objADDomains = Get-ADDomains -LoggingSQLServer $LoggingSQLServer -ExtDiscDBName $ExtDiscDBName -DomainsTableName $DomainsTableName
    ForEach ($Domain in $objADDomains) {
        Log-Append -strLogFileName $LogFileName -strLogText ("Enumerating the list of searchable domains")
        Log-Append -strLogFileName $LogFileName -strLogText ("`t- "+$Domain.DomainName+"`t"+$Domain.DomainNameFQDN+"`t"+$Domain.PDCFQDN)
    }

    $objClientsNoDN = Get-ClientsNoDN -CASSQLServer $SQLServer -SCCMDBName $SCCMDBName

    ForEach ($SCCMClient in $objClientsNoDN ) {
       # Log-Append -strLogFileName $LogFileName -strLogText (" ")
       # Log-Append -strLogFileName $LogFileName -strLogText ("NetBiosName :"+$SCCMClient.NetBios_name0)
       # Log-Append -strLogFileName $LogFileName -strLogText ("ResourceID :"+$SCCMClient.ResourceID)
       # Log-Append -strLogFileName $LogFileName -strLogText ("SiteCode :"+$SCCMClient.SMS_Assigned_Sites0)
       # Log-Append -strLogFileName $LogFileName -strLogText ("SMSUniqueIdentifier :"+$SCCMClient.SMS_Unique_Identifier0)
       # Log-Append -strLogFileName $LogFileName -strLogText ("DistinguishedName :"+$SCCMClient.Distinguished_Name0)
       # Log-Append -strLogFileName $LogFileName -strLogText ("Category :"+$SCCMClient.companyAttributeMachineCa0)
       # Log-Append -strLogFileName $LogFileName -strLogText ("Type :"+$SCCMClient.companyAttributeMachineTy0)
       # Log-Append -strLogFileName $LogFileName -strLogText ("Domain :"+$SCCMClient.Domain0)
       # Log-Append -strLogFileName $LogFileName -strLogText ("DomainName :"+$SCCMClient.DomainName0)
       # Log-Append -strLogFileName $LogFileName -strLogText ("FullDomainName :"+$SCCMClient.Full_Domain_Name0)
       # Log-Append -strLogFileName $LogFileName -strLogText ("ResourceDomainWorkgroup :"+$SCCMClient.Resource_Domain_OR_Workgr0)
        Log-Append -strLogFileName $LogFileName -strLogText ("Searching known domains for the computer named "+$SCCMClient.NetBios_name0)
        Foreach ( $Domain in $objADDomains) {
            $FoundDomain = $Null
            If ($Domain.DomainName -eq $SCCMClient.Domain0) { $FoundDomain = $Domain.DomainNameFQDN }
            If ($Domain.DomainName -eq $SCCMClient.Resource_Domain_OR_Workgr0) { $FoundDomain = $Domain.DomainNameFQDN }
            If ($Domain.DomainName -eq $SCCMClient.Full_Domain_Name0) { $FoundDomain = $Domain.DomainNameFQDN }
            If ($Domain.DomainNameFQDN -eq $SCCMClient.Domain0) { $FoundDomain = $Domain.DomainNameFQDN }
            If ($Domain.DomainNameFQDN -eq $SCCMClient.Resource_Domain_OR_Workgr0) { $FoundDomain = $Domain.DomainNameFQDN }
            If ($Domain.DomainNameFQDN -eq $SCCMClient.Full_Domain_Name0) { $FoundDomain = $Domain.DomainNameFQDN }

            If ($FoundDomain) {
                #Log-Append -strLogFileName $LogFileName -strLogText ("Found a matching domain named "+$Domain.DomainNameFQDN)
                #Log-Append -strLogFileName $LogFileName -strLogText ("Connecting to domain "+$Domain.DomainNameFQDN+" using DC named "+$Domain.PDCFQDN+" to find a computer named "+$SCCMClient.NetBios_name0)
                $ThisComputer = get-ComputerFromAD -DCServer $Domain.PDCFQDN -Computer $SCCMClient.NetBios_Name0
                if ( $ThisComputer ) { 
                    #Log-Append -strLogFileName $LogFileName -strLogText ("Found "+$SCCMClient.NetBios_Name0) 
                    If ($SCCMClient.SMS_Assigned_Sites0) {$SiteCode =  $SCCMClient.SMS_Assigned_Sites0} ELSE { $SiteCode =  $DefaultDDRSiteCode }
                    If ( $SCCMClient.SMS_Unique_Identifier0.ToString().length -ge 3  ) { $SMSUID = $SCCMClient.SMS_Unique_Identifier0.substring($SCCMClient.SMS_Unique_Identifier0.length - 36, 36) } ELSE { $SMSUID = $SCCMClient.NetBios_Name0 }
                    $Result = Create-DDR  -SiteCode $SiteCode -ResourceID  $SCCMClient.ResourceID -NetBiosName $SCCMClient.NetBios_Name0 -SMSUniqueIdentifier $SMSUID  -DistinguishedName  $ThisComputer.DistinguishedName -Category  $ThisComputer.companyAttributeMachineCategory  -Type $ThisComputer.companyAttributeMachineType  -DefaultDDRSiteCode $DefaultDDRSiteCode
                    If ( $Result = "Success" ) { Log-SQLDDRChange -LoggingSQLServer $LoggingSQLServer -ExtDiscDBName $ExtDiscDBName -LoggingTableName $LoggingTableName -ComputerName $SCCMClient.Netbios_Name0 -AD_DN $ThisComputer.DistinguishedName -AD_Category $ThosComputer.Category -AD_Type $ThisComputer.Type  -SCCM_DN $SCCMClient.Distinguished_Name0  -SCCM_Category $SCCMClient.companyAttributeMachineCa0 -SCCM_Type $SCCMClient.companyAttributeMachineTy0 -SCCM_SiteCode $SCCMClient.SMS_Assigned_Sites0 }
                    ELSE { Log-Append -strLogFileName $LogFileName -strLogText "Failed to create DDR" }
                }
                Else { 
                    #Log-Append -strLogFileName $LogFileName -strLogText ("Could not find computer "+$ComputerName+" on domain controller "+$DCServer)  
                }
                Break
            }
        }
        If ($FoundDomain -eq $Null)  { 
            #Log-Append -strLogFileName $LogFileName -strLogText ("Could not find a matching domain to search, searching for computer in all searchable domains" )
            Foreach ( $Domain in $objADDomains) {
               # Log-Append -strLogFileName $LogFileName -strLogText ("Connecting to domain "+$Domain.DomainNameFQDN+" using DC named "+$Domain.PDCFQDN+" to find a computer named "+$SCCMClient.NetBios_name0)
                $ThisComputer = $Null
                $ThisComputer = get-ComputerFromAD -DCServer $Domain.PDCFQDN -Computer $SCCMClient.NetBios_Name0
                if ( $ThisComputer ) {
                    Log-Append -strLogFileName $LogFileName -strLogText ("Found "+$SCCMClient.NetBios_Name0+" in domain "+$Domain.DomainNameFQDN+". Attempting to create DDR") 
                    If ($SCCMClient.SMS_Assigned_Sites0) {$SiteCode =  $SCCMClient.SMS_Assigned_Sites0} ELSE { $SiteCode =  $DefaultDDRSiteCode }
                    If ($SCCMClient.SMS_Unique_Identifier0.ToString().length -ge 3 ) { $SMSUID = $SCCMClient.SMS_Unique_Identifier0.substring($SCCMClient.SMS_Unique_Identifier0.length - 36, 36) } ELSE { $SMSUID = $SCCMClient.NetBios_Name0 }
                    $Result = Create-DDR  -SiteCode $SiteCode -ResourceID  $SCCMClient.ResourceID -NetBiosName $SCCMClient.NetBios_Name0 -SMSUniqueIdentifier $SMSUID  -DistinguishedName  $ThisComputer.DistinguishedName -Category  $ThisComputer.companyAttributeMachineCategory  -Type $ThisComputer.companyAttributeMachineType -DefaultDDRSiteCode $DefaultDDRSiteCode
                    If ( $Result = "Success" ) { Log-SQLDDRChange -LoggingSQLServer $LoggingSQLServer -ExtDiscDBName $ExtDiscDBName -LoggingTableName $LoggingTableName -ComputerName $SCCMClient.Netbios_Name0 -AD_DN $ThisComputer.DistinguishedName -AD_Category $ThosComputer.Category -AD_Type $ThisComputer.Type  -SCCM_DN $SCCMClient.Distinguished_Name0  -SCCM_Category $SCCMClient.companyAttributeMachineCa0 -SCCM_Type $SCCMClient.companyAttributeMachineTy0 -SCCM_SiteCode $SCCMClient.SMS_Assigned_Sites0 }
                    ELSE { Log-Append -strLogFileName $LogFileName -strLogText "Failed to create DDR" }
                    $FoundDomain = $Domain.DomainNameFQDN
                    Break
                }
                Else { 
                    #Log-Append -strLogFileName $LogFileName -strLogText ("Could not find computer "+$ComputerName+" on domain controller "+$DCServer)  
                }
            }
        } 
        If ($FoundDomain -eq $Null)  { 
            Log-Append -strLogFileName $LogFileName -strLogText ("Failed to find computer "+$SCCMClient.NetBios_name0+" in any searchable domain") 
        }
    }

    $objDDRsToMove = Get-ChildItem -Path ($DDRTempFolder+"\*.ddr")   
    If ($objDDRsToMove) {      
    $DDRFileCount = $objDDRsToMove.count
    Log-Append -strLogFileName $LogFileName -strLogText ("Moving "+$objDDRsToMove.count+" temporary DDR files to the DDR target Folder at "+$DDRTargetFolder)
        ForEach ($DDRFile in $objDDRsToMove ) {
            $ServerName = get-SiteServerName -SiteCode $DDRFile.Name.ToString().Substring(0,3) -objSitesList $objSMSSites
            $Result = Move-Item $DDRFile.FullName  ("\\"+$CASSiteServer+$DDRTargetFolder)  -Force 
            Log-Append -strLogFileName $LogFileName -strLogText ("\\"+$CASSiteServer+$DDRTargetFolder+$DDRFile.Name)
        }
    }
    ELSE {  Log-Append -strLogFileName $LogFileName -strLogText "There are no DDR files to move" }

    $SMSDisc = $Null
    Log-Append -strLogFileName $LogFileName -strLogText ("Script finished ")