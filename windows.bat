@echo off
echo ��������Windows��ȫ����...
echo.

:: ���ű��Ƿ��Թ���ԱȨ������
:: ������ԱȨ�޵ĸĽ�����
fltmc >nul 2>&1 || (
    echo �˽ű���Ҫ����ԱȨ�޲������С�
    echo ���Ҽ�����ű���ѡ��"�Թ���Ա�������"��
    goto :end
)

echo ��1���������������ϸ�����Ҫ�� (1 = ����, 0 = ����)
echo [version] >account.inf
echo signature="$CHICAGO$" >>account.inf
echo [System Access] >>account.inf
:: �����ʻ����븴����Ҫ��
echo PasswordComplexity=1 >>account.inf
:: �޸��ʻ�������С����Ϊ8
echo MinimumPasswordLength=8 >>account.inf

echo ��2�� �޸�ǿ��������ʷΪ3
echo passwordhistorysize=3 >>account.inf
:: ��ʾ�û����������֮ǰ���и���
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v PasswordExpiryWarning /t REG_DWORD /d 0x0000000e /f

echo ��3�� �����ʻ�����ʱ��\������ֵ\��λ�ʻ�������������ʱ��
:: �趨�ʻ�������ֵΪ6��
echo LockoutBadCount=6 >>account.inf
:: ���á���λ�ʻ�������������3���Ӻ������ʻ���������������ʱ��
echo ResetLockoutCount=3 >>account.inf
::  �����ʻ�����ʱ��Ϊ5����
echo LockoutDuration=3 >>account.inf
secedit /configure /db account.sdb /cfg account.inf /log account.log /quiet

echo ��4������Guest�ʻ�
echo EnableGuestAccount=0 >>account.inf
del account.*


::   echo ��5������Ƿ���ڿտ���еĻ��г���
::   :: ������ʱ�ļ��洢�û��б�
::   net user > userlist.tmp 
::   
::   :: ��ȡ�û��˻���(����ǰ���к��������)
::   setlocal enabledelayedexpansion
::   set "count=0"
::   del users.txt 2>nul
::   for /f "tokens=*" %%a in (userlist.tmp) do (
::       set /a "count+=1"
::       if !count! GTR 4 (
::           echo %%a | findstr /i /c:"����ɹ����" >nul
::           if !errorlevel! neq 0 (
::               echo %%a | findstr /i /c:"-----------" >nul
::               if !errorlevel! neq 0 (
::                   for %%u in (%%a) do echo %%u >> users.txt
::               )
::           )
::       )
::   )
::   endlocal
::   
::   :: ���ÿ���û��Ƿ��п�����
::   echo ���ڼ���û�����״̬...
::   echo.
::   echo �������¿������˻�:
::   echo ----------------------------------------
::   set "emptyCount=0"
::   for /f %%u in (users.txt) do (
::       net user %%u | findstr /i "����������" >nul
::       if %errorlevel% equ 0 (
::           echo - %%u
::           set /a "emptyCount+=1"
::       )
::   )
::   
::   :: ������ʱ�ļ�
::   del userlist.tmp 2>nul
::   del users.txt 2>nul
::   
::   echo.
::   if %emptyCount% equ 0 (
::       echo δ���ֿ������˻���
::   ) else (
::       echo ����: ϵͳ�д��� %emptyCount% ���������˻�!
::       echo ��������Ϊ��Щ�˻�����ǿ��������ǿϵͳ��ȫ�ԡ�
::   )


echo ��6�������������ǰ��ʾ����, ���뵽��14��ǰ��ʾ�û�����.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Policy" /v "PasswordExpiryWarning" /t REG_DWORD /d 0x0000000e /f

echo ��7��������Ļ�������� - ʹ��Ĭ�ϵ�(��)��Ļ��������ʱ����Ϊ15����,���ûָ�ʱ��ʾ��¼��Ļ
:: ������Ļ��������ΪĬ��(��)...
reg add "HKCU\Control Panel\Desktop" /v "ScreenSaveActive" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Desktop" /v "SCRNSAVE.EXE" /t REG_SZ /d "" /f

:: ������Ļ�����ȴ�ʱ��Ϊ15����(900��)
echo ������Ļ�����ȴ�ʱ��Ϊ15����...
reg add "HKCU\Control Panel\Desktop" /v "ScreenSaveTimeOut" /t REG_SZ /d "900" /f

:: ���ûָ�ʱ��ʾ��¼��Ļ(���뱣��)
echo ���ûָ�ʱ��ʾ��¼��Ļ...
reg add "HKCU\Control Panel\Desktop" /v "ScreenSaverIsSecure" /t REG_SZ /d "1" /f

echo ��8�� ���÷���������ͣ�Ựǰ����Ŀ���ʱ��Ϊ15����...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "AutoDisconnect" /t REG_DWORD /d 15 /f

echo ��9������Guest�˻�
net user guest /active:no

echo ��10�����������û�����Ȩ�ޣ���ֹö�ٱ����ʺź͹���...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "RestrictAnonymous" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "RestrictAnonymousSAM" /t REG_DWORD /d 1 /f

::  echo��11����鹲���ļ��е�Ȩ�������Ƿ�ȫ
::  :: ������ʱ�ļ��洢�����б�
::  set "tempShareList=%temp%\share_list.tmp"
::  set "tempEveryoneShares=%temp%\everyone_shares.tmp"
::  del /f /q %tempShareList% 2>nul
::  del /f /q %tempEveryoneShares% 2>nul
::  
::  :: ��ȡ���й����ļ����б�
::  net share > %tempShareList%
::  
::  :: ��ǹ����б�ʼ��
::  set "shareListStarted="
::  set "everyoneShareCount=0"
::  
::  :: ���������б����ÿ�������Ȩ��
::  for /f "tokens=*" %%a in (%tempShareList%) do (
::      set "line=%%a"
::      
::      :: ��⹲���б�ʼ�У�����"--------"����֮��
::      if defined shareListStarted (
::          :: ��ȡ��������ÿ�е�һ���ո�ǰ�Ĳ��֣�
::          for /f "tokens=1" %%s in ("!line!") do (
::              set "sharename=%%s"
::              
::              :: �ų���֪��ϵͳ����
::              if /i not "!sharename!"=="ADMIN$" (
::                  if /i not "!sharename!"=="C$" (
::                      if /i not "!sharename!"=="D$" (
::                          if /i not "!sharename!"=="IPC$" (
::                              if /i not "!sharename!"=="PRINT$" (
::                                  :: ��鹲��Ȩ���Ƿ����Everyone
::                                  echo ��鹲��: !sharename!
::                                  net share !sharename! | findstr /i /c:"Everyone" >nul
::                                  if !errorlevel! equ 0 (
::                                      echo ���ְ���'Everyone'Ȩ�޵Ĺ���: !sharename!
::                                      echo !sharename! >> %tempEveryoneShares%
::                                      set /a "everyoneShareCount+=1"
::                                  )
::                              )
::                          )
::                      )
::                  )
::              )
::          )
::      ) else (
::          echo !line! | findstr /c:"--------" >nul
::          if !errorlevel! equ 0 (
::              set "shareListStarted=1"
::          )
::      )
::  )
::  
::  :: ������
::  echo.
::  if %everyoneShareCount% gtr 0 (
::      echo ������ %everyoneShareCount% ������'Everyone'����Ȩ�޵��ļ��С�
::      echo ����'Everyone'Ȩ�޵Ĺ����б��ѱ��浽: %tempEveryoneShares%
::      echo.
::      echo �������:
::      echo 1. ����б��еĹ����ļ��У�ȷ���Ƿ���Ҫ��������
::      echo 2. �Բ���Ҫ�������ʵĹ���ʹ�����������޸�Ȩ��:
::      echo    net share ������ /grant:�û���,Ȩ��
::      echo    (����: net share MyDocs /grant:Users,Read)
::  ) else (
::      echo δ���ְ���'Everyone'����Ȩ�޵��ļ��С�
::  )

echo (12) ���ò���ʾ��¼��Ļ�ϵ����һ���û���...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "DontDisplayLastUserName" /t REG_DWORD /d 1 /f

echo (13) ����Դ·�ɹ�������...
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableIPSourceRouting" /t REG_DWORD /d 2 /f

echo ��14������SYN��������...
:: ����SYN��������
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v SynAttackProtect /t REG_DWORD /d 2 /f

:: ���������Ӷ��д�С
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpMaxHalfOpen /t REG_DWORD /d 1000 /f

:: �����������������ֵ
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpMaxHalfOpenRetried /t REG_DWORD /d 800 /f

:: ����SYN-ACK���Դ���
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpMaxPortsExhausted /t REG_DWORD /d 5 /f

:: ����SYN Cookie����
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpTimedWaitDelay /t REG_DWORD /d 30 /f

echo (15)  ����ICMP��Ӧ����(��ֹPing Flood)...
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnableICMPRedirect /t REG_DWORD /d 0 /f

echo (16) ����ʧЧ���ؼ��...
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnableDeadGWDetect /t REG_DWORD /d 0 /f

echo (17) ����·�ɷ��ֹ���...
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnableRouterDiscovery /t REG_DWORD /d 0 /f

echo (18) ����tcp��Ƭ����...
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnablePMTUDiscovery /t REG_DWORD /d 1 /f

echo (19) ����WindowsӲ��Ĭ�Ϲ���...
:: �����Զ��������$
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareServer /t REG_DWORD /d 0 /f
:: ����ADMIN$����
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareWks /t REG_DWORD /d 0 /f
:: ����IPC$����
sc config lanmanserver start=disabled >nul 2>&1


echo ��20������Windows�Զ���¼...
:: ����Զ���¼��Ϣ
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName /f >nul 2>&1
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword /f >nul 2>&1
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /f >nul 2>&1

:: ����AutoAdminLogonΪ0�������Զ���¼��
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_SZ /d "0" /f

echo ��21������Simple TCP/IP����(�������)
sc config stisvc start=disabled >nul 2>&1
sc stop stisvc >nul 2>&1

echo ��22������SMTP����(�������)
sc config SMTPSVC start=disabled >nul 2>&1
sc stop SMTPSVC >nul 2>&1

echo ��23������WINS����(�������)
sc config Wins start=disabled >nul 2>&1
sc stop Wins >nul 2>&1


echo ��24������DHCP Server����
sc config DHCPServer start=disabled >nul 2>&1
sc stop DHCPServer >nul 2>&1


echo ��25������Message Queuing����
sc config MSMQ start=disabled >nul 2>&1
sc stop MSMQ >nul 2>&1


echo ��26������SMB����SMB�����������ã�
:: ����SMB1�ͻ��˺ͷ��������
dism /online /disable-feature /featurename:SMB1Protocol-Client /norestart >nul 2>&1
dism /online /disable-feature /featurename:SMB1Protocol-Server /norestart >nul 2>&1

:: ����SMB2/3�ͻ��˺ͷ��������
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB2 /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v SMB2 /t REG_DWORD /d 0 /f >nul 2>&1

:: ֹͣ������SMB����
sc config LanmanServer start=disabled >nul 2>&1
sc config LanmanWorkstation start=disabled >nul 2>&1
sc stop LanmanServer /y >nul 2>&1
sc stop LanmanWorkstation /y >nul 2>&1
echo SMB�����ѽ���!

echo ��27��������������˲��ԣ����ñ��ز�������˲����������ÿ���Ҫ����Ϊ���ɹ����͡�ʧ�ܡ���Ҫ���
echo [version] >audit.inf
echo signature="$CHICAGO$" >>audit.inf
echo [Event Audit] >>audit.inf
echo ������˶������
echo AuditObjectAccess= 3 >>audit.inf
echo ���������Ȩʹ��
echo AuditPrivilegeUse= 3 >>audit.inf
echo �������ϵͳ�¼�
echo AuditSystemEvents=3 >>audit.inf
echo ������˽��̸���
echo AuditProcessTracking=3 >>audit.inf
echo ������˲��Ը���
echo AuditPolicyChange=3 >>audit.inf
echo �������Ŀ¼�������
echo AuditDSAccess=3 >>audit.inf
echo ��������ʻ�����
echo AuditAccountManage=3 >>audit.inf
echo ��������ʻ���½�¼�
echo AuditAccountLogon=3 >>audit.inf
echo ������˵�½�¼�
echo AuditLogonEvents=3 >>audit.inf
echo gpupdate /force
secedit /configure /db audit.sdb /cfg audit.inf /log audit.log /quiet
del audit.*

echo ��28�����ò���ȷ����Windows����ʱ��ͬ������
echo ��������Windows Time����...
net start w32time
echo ������״̬:
sc query w32time | findstr /i "STATE"


echo ��29������Ƿ�װ�ķ��������:
wmic /namespace:\\root\SecurityCenter2 path AntiVirusProduct get displayName, productState /format:list 2>nul
echo �����:
set "found=0"
for /f "tokens=*" %%a in ('wmic /namespace:\\root\SecurityCenter2 path AntiVirusProduct get displayName 2^>nul') do (
    if not "%%a"=="" (
        if not "%%a"=="DisplayName" (
            set "found=1"
        )
    )
)
if %found%==1 (
    echo ϵͳ���Ѱ�װ�����������
) else (
    echo δ��⵽�����������װ!
    echo ����������װ�����÷���������Ա���ϵͳ��ȫ��
)

:end
echo.
echo ע�⣺���ָ��Ŀ�����Ҫ�������������������ȫ��Ч��
echo �ű�ִ����ϡ���������˳�...
pause >nul    