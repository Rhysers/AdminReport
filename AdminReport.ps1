Import-Module ActiveDirectory
$Forrest = Get-ADForest
$domains = $Forrest.Domains | sort -Descending
$output = "<H1>Administrator Report</H1><p>This email contains a wide chart and it may be difficult to view in the reading pane.</p><h2>Domain: $($Domains[0])</h2>"
$Groups = @("Schema Admins","Enterprise Admins")
$Attachments = @()
foreach ($Group in $Groups){
    $Members = @()
    $members += Get-ADGroup $Group -Server $domains[0] | Get-ADGroupMember -Recursive | Get-ADUser -Properties UserPrincipalName -ErrorAction SilentlyContinue
    $members = $Members | Sort-Object -Property Name
    $temp = $members | select Name,Enabled,DistinguishedName,UserPrincipalName | Format-Table -AutoSize | Out-String -Width 10000
    $output += "<h3>$Group</h3>"
    if ($members.count -eq 0){
        $output+="<p>None</p>"
    }else{
        $output += "<pre>$temp</pre>"
        $Members | Export-Csv -NoTypeInformation -Path "C:\temp\$($Domains[0]) - $Group Members.csv"
        $Attachments += "C:\temp\$($Domains[0]) - $Group Members.csv"
    }
}
foreach ($domain in $domains){
    $Members = @()
    $members += Get-ADGroup "Domain Admins" -Server $domain | Get-ADGroupMember -Recursive | Get-ADUser -Properties UserPrincipalName -ErrorAction SilentlyContinue
    $members = $Members | Sort-Object -Property Name
    $temp = $Members | select Name,Enabled,DistinguishedName,UserPrincipalName | Format-Table -AutoSize | Out-String -Width 10000
    if($domain -ne $Domains[0]){
        $output += "<h2>Domain: $domain</h2>"
    }
    $output += "<H3>Domain Admins</H3>"
    if ($Members.Count -eq 0){
        $output+="<p>None</p>"
    }else{
        $output += "<pre>$temp</pre>"
        $members | Export-Csv -NoTypeInformation -Path "C:\temp\$Domain - Domain Admins Members.csv"
        $Attachments += "C:\temp\$Domain - Domain Admins Members.csv"
    }
}
Send-MailMessage -To "you@example.com" -From "NoReply@example.com" -Subject "Administrator Report ($($Domains[0]))" -Body $output -BodyAsHtml -SmtpServer imail.senate.gov -Attachments $Attachments