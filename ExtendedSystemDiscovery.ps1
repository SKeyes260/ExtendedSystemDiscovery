param([string]$SiteServer, [string]$SiteCode, [string]$InstanceName  )

PowerShell { Import-Module -Global ActiveDirectory -Force }

# Fill the objSMSSites array from the CAS WMI
Function Get-SMSSites() {
[CmdletBinding()]   
PARAM 
(   [Parameter(Position=1)] $SiteServer,
    [Parameter(Position=2)] $SiteCode )   
    
    Log-Append -strLogFileName $LogFileName -strLogText ("Identifying Primary Sites")
    $objSMSSites = Get-WmiObject -ComputerName $SiteServer -Namespace ("root\sms\Site_"+$SiteCode) -Query "SELECT * FROM SMS_SITE Order By SiteCode"
    Return $objSMSSites
}


# Fill the objDomains array with SQL table data from SCCM_EXT 
Function Get-ADDomains() {
[CmdletBinding()]   
PARAM 
(   [Parameter(Position=1)] $SQLServer,
    [Parameter(Position=2)] $ExtDiscDBName,
    [Parameter(Position=3)] $DomainsTableName
)   

    $objADDomains = @()
    $SqlConnection = New-Object System.Data.SqlClient.SqlConnection
    $SqlConnection.ConnectionString = "Server=$SQLServer;Database=$ExtDiscDBName;Integrated Security=True"
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
    [Parameter(Position=7)] $Type  )  
        
    $SMSDisc.DDRNew("System","SA_EXT_Disc",$SiteCode) 

    If (($SMSUniqueIdentifier) -AND ($SMSUniqueIdentifier -NE '')  -AND ($SMSUniqueIdentifier -NE ' '))  {
        If ($SMSUniqueIdentifier.length -ge 36) { 
            $SMSUID = $SMSUniqueIdentifier.substring($SMSUniqueIdentifier.length - 36, 36)
            $SMSDisc.DDRAddString("SMS Unique Identifier", ($SMSUniqueIdentifier), 64,  $ADDPROP_GUID + $ADDPROP_KEY)
         } 
         ELSE { 
             $SMSUID = "NOGUID"  
         }
    }
        
    $SMSDisc.DDRAddString("Netbios Name",                                        $NetBiosName,         16,  $ADDPROP_NAME + $ADDPROP_KEY)  
    $SMSDisc.DDRAddString("Distinguished Name",                                  $DistinguishedName,   256, $ADDPROP_NONE)  
    If ( $Category ) { $SMSDisc.DDRAddString("companyAttributeMachineCategory",  $Category,            32,  $ADDPROP_NONE)  }
    If ( $Type )     { $SMSDisc.DDRAddString("companyAttributeMachineType",      $Type,                32,  $ADDPROP_NONE)  }

    $Result = $SMSDisc.DDRWrite($DDRTempFolder+$SiteCode+"-"+$NetBiosName+"-"+$SMSUID+".DDR")
    $TestFile = Get-Item -LiteralPath  ($DDRTempFolder+$SiteCode+"-"+$NetBiosName+"-"+$SMSUID+".DDR")
    If ($TestFile) { 
        Log-Append -strLogFileName $LogFileName  -strLogText ("Created DDR "+$DDRTempFolder+$SiteCode+"-"+$NetBiosName+"-"+$SMSUID+".DDR")
        Return "Success" 
    }
    ELSE {
        Log-Append -strLogFileName $LogFileName  -strLogText ("Failed to create DDR "+$DDRTempFolder+$SiteCode+"-"+$NetBiosName+"-"+$SMSUID+".DDR")
        Return "Failed" 
    }
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
(   [Parameter(Position=1)] $SQLServer,
    [Parameter(Position=2)] $ExtDiscDBName, 
    [Parameter(Position=3)] $LoggingTableName, 
    [Parameter(Position=4)] $ComputerName,
    [Parameter(Position=5)] $AD_DN,
    [Parameter(Position=6)] $AD_Category,
    [Parameter(Position=7)] $AD_Type,
    [Parameter(Position=12)] $SCCM_DN,
    [Parameter(Position=13)] $SCCM_Category,
    [Parameter(Position=14)] $SCCM_Type,
    [Parameter(Position=15)] $SCCM_SiteCode,
    [Parameter(Position=16)] $SMSClientGUID)

    If (!$SQLConnection) {
        $SQLConnection =  New-Object System.Data.SqlClient.SqlConnection  
        $SQLConnection.ConnectionString = "Server=$SQLServer;Database=$ExtDiscDBName;Integrated Security=True"
        $SQLConnection.Open()
    }
    $cmd = $SQLConnection.CreateCommand()
    $cmd.CommandText ="INSERT INTO $LoggingTableName  (ComputerName,AD_DN,AD_Category,AD_Type,SCCM_DN,SCCM_Category,SCCM_Type,SCCM_SiteCode,SMSClientGUID,DiscoveryMethod) 
                        VALUES( '$ComputerName','$AD_DN','$AD_Category','$AD_Type','$SCCM_DN','$SCCM_Category','$SCCM_Type','$SCCM_SiteCode','$SMSClientGuid','ExtSysDiscV3' );"
    $Result = $cmd.ExecuteNonQuery()
    $Result = $SQLConnection.Close
}


# Connect to the SCCM CAS to identify all systems missing their distinguishedName, category or type 
Function Get-ClientsNoDN() {
[CmdletBinding()]   
PARAM 
(   [Parameter(Position=1)] $SQLServer,
    [Parameter(Position=2)] $SiteCode )    

        $objSCCMComputers = @()
        $SqlConnection = New-Object System.Data.SqlClient.SqlConnection
        $SqlConnection.ConnectionString = "Server=$SQLServer;Database=$SCCMDBName;Integrated Security=True"
        $SqlCmd = New-Object System.Data.SqlClient.SqlCommand
        $SqlCmd.CommandText = "SELECT TOP (100) PERCENT dbo.v_RA_System_SMSAssignedSites.SMS_Assigned_Sites0, dbo.v_R_System.ResourceID,  
                dbo.v_R_System.companyAttributeMachineCa0, dbo.v_R_System.companyAttributeMachineTy0, dbo.v_R_System.Distinguished_Name0, 
                dbo.v_R_System.Full_Domain_Name0,dbo.v_R_System.Netbios_Name0, dbo.v_R_System.Resource_Domain_OR_Workgr0, dbo.v_R_System.SMS_Unique_Identifier0
                FROM dbo.v_R_System LEFT OUTER JOIN dbo.v_RA_System_SMSAssignedSites ON dbo.v_R_System.ResourceID = dbo.v_RA_System_SMSAssignedSites.ResourceID
                WHERE (dbo.v_R_System.Distinguished_Name0 IS NULL OR dbo.v_R_System.Distinguished_Name0 = '' OR dbo.v_R_System.Distinguished_Name0 = ' ') AND (dbo.v_R_System.Netbios_Name0 <> 'Unknown') Order By dbo.v_R_System.ResourceID DESC "
        $SqlCmd.Connection = $SqlConnection
        $SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
        $SqlAdapter.SelectCommand = $SqlCmd
        $objSCCMComputers = New-Object System.Data.Datatable
        $NumRows = $SqlAdapter.Fill($objSCCMComputers)
        If (!$NumRows) {$NumRows = 0}
        $SqlConnection.Close()
        ForEach ( $Found in $objSCCMComputers ) {
            Log-Append -strLogFileName $LogFileName -strLogText ($Found.Netbios_Name0)
        }
        return $objSCCMComputers
}


##############################
#  MAIN
##############################

#Define standard static variables
$ADDPROP_NONE  = 0x0
$ADDPROP_GUID  = 0x2
$ADDPROP_KEY   = 0x8
$ADDPROP_ARRAY = 0x10
$ADDPROP_NAME  = 0x44
$ADDPROP_NAME2 = 0x84

$TodaysDate = Get-Date

#Define environment specific  variables
$ScriptPath         = $PSScriptRoot
$LoggingFolder      = ($ScriptPath+"\Logs\")
$DDRTempFolder      = ($ScriptPath+"\TempDDRs\")
$ExtDiscDBName      = "SCCM_EXT"
$DomainsTableName   = "tbl_ExtDiscDomains"
$LoggingTableName   = "tbl_ExtDiscLogging"
$DaysInactive       = 90  
$InactivityDate     = (Get-Date).Adddays(-($DaysInactive)) 

# Set parameter defaults
$PassedParams =  (" -SiteServer "+$SiteServer+" -SiteCode "+$SiteCode+" -SQLServer "+$SQLServer+" -InstanceName "+$InstanceName)
If (!$SiteServer)   { $SiteServer   = "GISSSCCMDEV2"                 }
If (!$SiteCode)     { $SiteCode     = "T00"                         }
If (!$InstanceName) { $InstanceName = "ExtSysDisc-DEV" }

# Lookup the SCCM site definition to populate glkobal variables
$objSiteDefinition = Get-WmiObject -ComputerName $SiteServer -Namespace ("root\sms\Site_"+$SiteCode) -Query ("SELECT * FROM sms_sci_sitedefinition WHERE SiteCode = '"+$SiteCode+"'")
$SCCMDBName = $objSiteDefinition.SQLDatabaseName
$SQLServer = $objSiteDefinition.SQLServerName

# Get the logging prepared
If (!(Test-Path $LoggingFolder))  { $Result = New-Item $LoggingFolder -type directory }
If (!(Test-Path $DDRTempFolder))  { $Result = New-Item $DDRTempFolder -type directory }
$LogFileName = ($LoggingFolder+$InstanceName+"-"+$TodaysDate.Year+$TodaysDate.Month.ToString().PadLeft(2,"0")+$TodaysDate.Day.ToString().PadLeft(2,"0")+".log")
    
# Set variables that use parameters
$DefaultDDRSiteCode = $SiteCode # used for clients with no assigned site code
$DDRTargetFolder = ("\sms_"+$SiteCode+"\inboxes\auth\ddm.box")   #must include trailing \

# Define global Arrays
$objSMSSites = @()
$objADDomains = @()
$objLogging = @()
$SCCMComputers = @()
$FoundComputers = @()
$objDDRsToMove = @()

Log-Append -strLogFileName $LogFileName -strLogText ("Script Started using command line parameters : "+$PassedParams )
Log-Append -strLogFileName $LogFileName -strLogText ("The actual values being used are : -SiteServer "+$SiteServer+" -SiteCode "+$SiteCode+" -SQLServer "+$SQLServer+" -InstanceName "+$InstanceName)

#Load the SCCM SDK DLL
Log-Append -strLogFileName $LogFileName -strLogText ("Creating an instance of the com object SMSResGen.SMSResGen.1" )
If (!$SMSDisc) {
    Try { &regsvr32 /s ($ScriptPath+"\SCCMDLLs\NewDLLs\smsrsgen.dll")
        $SMSDisc = New-Object -ComObject "SMSResGen.SMSResGen.1" }
    Catch { 
        Try {
            &regsvr32 /s ($ScriptPath+"\SCCMDLLs\OldDLLs\smsrsgen.dll")
            $SMSDisc = New-Object -ComObject "SMSResGen.SMSResGen.1" 
        }
        Catch { Log-Append -strLogFileName $LogFileName -strLogText "Failed to load COM object SMSResGen.SMSResGen.1" }
    }
}

#Get a list of the  site codes in SCCM 
Log-Append -strLogFileName $LogFileName -strLogText ("Getting SCCM primary site information")
$objSMSSites = Get-SMSSItes -SiteServer $SiteServer  -SiteCode $SiteCode
ForEach ($Site in $objSMSSites){ Log-Append -strLogFileName $LogFileName -strLogText (" - "+$Site.ServerName+"    "+$Site.SiteCode+"    "+$Site.InstallDir) }

# Get a list of all of the discoverable domains from SQL Ext table
Log-Append -strLogFileName $LogFileName -strLogText ("Getting list of SCCM discovered domains from SQL")
$objADDomains = Get-ADDomains -SQLServer $SQLServer -ExtDiscDBName $ExtDiscDBName -DomainsTableName $DomainsTableName

# Get a list of all systems from SYSTEM_DISC that are missing their distinguished name 
Log-Append -strLogFileName $LogFileName -strLogText ("Getting list of SCCM clients with no DistinguishedName in their discovery record")
$SCCMComputers = Get-ClientsNoDN -SQLServer $SQLServer -SiteCode $SiteCode
Log-Append -strLogFileName $LogFileName -strLogText ("Found "+($SCCMComputers.Count)+" systems with no distinguished name")

Log-Append -strLogFileName $LogFileName -strLogText ("Iterating through list of SCCM clients missing distinguished names to retrieve AD data ")
ForEach ($SCCMComputer in $SCCMComputers ) {
    # Log-Append -strLogFileName $LogFileName -strLogText ("**** Existing SCCM Information ")
    # Log-Append -strLogFileName $LogFileName -strLogText ("NetBiosName :"+$SCCMComputer.NetBios_name0)
    # Log-Append -strLogFileName $LogFileName -strLogText ("ResourceID :"+$SCCMComputer.ResourceID)
    # Log-Append -strLogFileName $LogFileName -strLogText ("SiteCode :"+$SCCMComputer.SMS_Assigned_Sites0)
    # Log-Append -strLogFileName $LogFileName -strLogText ("SMSUniqueIdentifier :"+$SCCMComputer.SMS_Unique_Identifier0)
    # Log-Append -strLogFileName $LogFileName -strLogText ("CompanyMachineType :"+$SCCMComputer.companyAttributeMachineTy0)
    # Log-Append -strLogFileName $LogFileName -strLogText ("CompanyMachineCategory :"+$SCCMComputer.companyAttributeMachineCa0)

    $ADComputers = @()
    ForEach ($objDomain in $objADDomains ) {
        #Log-Append -strLogFileName $LogFileName -strLogText ("Searching the domain named "+$objDomain.DomainNameFQDN+" for computers named "+$SCCMComputer.NetBios_name0+" using DC named "+$objDomain.PDCFQDN)
        $intFoundComputers = 0
        TRY   { 
            $ADComputers = Get-ADComputer -Server $objDomain.PDCFQDN -Filter ('Name -eq "'+$SCCMComputer.NetBios_Name0+'"')   -Properties *  -ErrorAction SilentlyContinue  
            If ( $ADComputers ) { BREAK }
        }
        CATCH { Log-Append -strLogFileName $LogFileName -strLogText ("Failed to connect to domain named "+$objDomain.DomainNameFQDN) }
    }
    If ( $intFoundComputers = 0 ) {
        Log-Append -strLogFileName $LogFileName -strLogText ("Failed to find computer named "+$SCCMComputer.NetBios_Name0+" in any searchable domain")
    }

    Foreach ( $ADComputer in $ADComputers) {
        If ( $ADComputer.Name -eq $SCCMComputer.netBios_Name0 ) {
            # Clean data before matching
            If ( !$ADComputer.CompanyAttributeMachineCategory -or $ADComputer.CompanyAttributeMachineCategory -eq '' -or $ADComputer.CompanyAttributeMachineCategory -eq ' ') { $ADComputer.CompanyAttributeMachineCategory = $Null }
            If ( !$ADComputer.CompanyAttributeMachineType     -or $ADComputer.CompanyAttributeMachineType     -eq '' -or $ADComputer.CompanyAttributeMachineType     -eq ' ') { $ADComputer.CompanyAttributeMachineType     = $Null }
            If ( !$SCCMComputer.CompanyAttributeMachineCa0    -or $SCCMComputer.CompanyAttributeMachineCa0    -eq '' -or $SCCMComputer.CompanyAttributeMachineCa0    -eq ' ') { $SCCMComputer.CompanyAttributeMachineCa0    = $Null }
            If ( !$SCCMComputer.CompanyAttributeMachineTy0    -or $SCCMComputer.CompanyAttributeMachineTy0    -eq '' -or $SCCMComputer.CompanyAttributeMachineTy0    -eq ' ') { $SCCMComputer.CompanyAttributeMachineTy0    = $Null }

            Log-Append -strLogFileName $LogFileName -strLogText  ("Found matching name in AD ( "+$SCCMComputer.NetBios_name0+" )")
            #Log-Append -strLogFileName $LogFileName -strLogText  ("AD Name("+$ADComputer.Name+")`t ADMachineType("+$ADComputer.CompanyAttributeMachineType+")`t ADMachineCategory("+$ADComputer.CompanyAttributeMachineCategory+")`t DistinguishedName("+$ADComputer.DistinguishedName+")")
            #Log-Append -strLogFileName $LogFileName -strLogText  ("CM Name("+$SCCMComputer.NetBios_Name0+")`t CMMachineType("+$SCCMComputer.CompanyAttributeMachineTy0+")`t CMMachineCategory("+$SCCMComputer.CompanyAttributeMachineCa0+")`t DistinguishedName("+$SCCMComputer.Distinguished_name0+")")

            If ($SCCMComputer.SMS_Assigned_Sites0.ToString().length -eq 3 ) {$UseSiteCode =  $SCCMComputer.SMS_Assigned_Sites0} ELSE { $UseSiteCode = $SiteCode }
            $Result = Create-DDR  -SiteCode $UseSiteCode -ResourceID  $SCCMComputer.ResourceID -NetBiosName $SCCMComputer.NetBios_Name0 -SMSUniqueIdentifier $SCCMComputer.SMS_Unique_Identifier0  -DistinguishedName  $ADComputer.DistinguishedName -Category  $ADComputer.companyAttributeMachineCategory  -Type $ADComputer.companyAttributeMachineType 
            If ( $Result = "Success" ) { Log-SQLDDRChange -SQLServer $SQLServer -ExtDiscDBName $ExtDiscDBName -LoggingTableName $LoggingTableName -ComputerName $SCCMComputer.Netbios_Name0 -AD_DN $ADComputer.DistinguishedName -AD_Category $ADComputer.companyAttributeMachineCategory -AD_Type $ADComputer.companyAttributeMachineType  -SCCM_DN $SCCMComputer.Distinguished_Name0  -SCCM_Category $SCCMComputer.companyAttributeMachineCa0 -SCCM_Type $SCCMComputer.companyAttributeMachineTy0 -SCCM_SiteCode $SCCMComputer.SMS_Assigned_Sites0 -SMSClientGUID $SCCMComputer.SMS_Unique_Identifier0 }
            ELSE { Log-Append -strLogFileName $LogFileName -strLogText "Failed to create DDR" }
        }
    }
}


# Move the DDR files to the CAS
ForEach ( $SCCMSite in $objSMSSites ) {
    $objDDRsToMove = Get-ChildItem -Path ($DDRTempFolder+$SCCMSite.SiteCode+"*.ddr")   
    If ($objDDRsToMove.Count -gt 0) {
        ForEach ($DDRFile in $objDDRsToMove ) {
            If ( $DDRFile.Name.ToString().Substring(0,3) -eq $SCCMSite.SiteCode ) {
                $Result = Move-Item $DDRFile.FullName  ("\\"+$SiteServer+$DDRTargetFolder)  -Force 
                Log-Append -strLogFileName $LogFileName -strLogText ("Moving DDR to CAS server \\"+$SiteServer+$DDRTargetFolder+$DDRFile.Name)
            }
        }
    }
}

$SMSDisc = $Null
Log-Append -strLogFileName $LogFileName -strLogText ("Script finished ")