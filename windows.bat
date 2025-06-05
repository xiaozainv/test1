@echo off
echo 正在配置Windows安全策略...
echo.

:: 检查脚本是否以管理员权限运行
:: 检查管理员权限的改进方法
fltmc >nul 2>&1 || (
    echo 此脚本需要管理员权限才能运行。
    echo 请右键点击脚本并选择"以管理员身份运行"。
    goto :end
)

echo （1）设置密码必须符合复杂性要求 (1 = 启用, 0 = 禁用)
echo [version] >account.inf
echo signature="$CHICAGO$" >>account.inf
echo [System Access] >>account.inf
:: 开启帐户密码复杂性要求
echo PasswordComplexity=1 >>account.inf
:: 修改帐户密码最小长度为8
echo MinimumPasswordLength=8 >>account.inf

echo （2） 修改强制密码历史为3
echo passwordhistorysize=3 >>account.inf
:: 提示用户在密码过期之前进行更改
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v PasswordExpiryWarning /t REG_DWORD /d 0x0000000e /f

echo （3） 配置帐户锁定时间\锁定阈值\复位帐户锁定计数器”时间
:: 设定帐户锁定阀值为6次
echo LockoutBadCount=6 >>account.inf
:: 配置“复位帐户锁定计数器（3分钟后重置帐户锁定计数器）”时间
echo ResetLockoutCount=3 >>account.inf
::  配置帐户锁定时间为5分钟
echo LockoutDuration=3 >>account.inf
secedit /configure /db account.sdb /cfg account.inf /log account.log /quiet

echo （4）禁用Guest帐户
echo EnableGuestAccount=0 >>account.inf
del account.*


::   echo （5）检查是否存在空口令，有的话列出来
::   :: 创建临时文件存储用户列表
::   net user > userlist.tmp 
::   
::   :: 提取用户账户名(跳过前四行和最后两行)
::   setlocal enabledelayedexpansion
::   set "count=0"
::   del users.txt 2>nul
::   for /f "tokens=*" %%a in (userlist.tmp) do (
::       set /a "count+=1"
::       if !count! GTR 4 (
::           echo %%a | findstr /i /c:"命令成功完成" >nul
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
::   :: 检查每个用户是否有空密码
::   echo 正在检查用户密码状态...
::   echo.
::   echo 发现以下空密码账户:
::   echo ----------------------------------------
::   set "emptyCount=0"
::   for /f %%u in (users.txt) do (
::       net user %%u | findstr /i "密码必须更改" >nul
::       if %errorlevel% equ 0 (
::           echo - %%u
::           set /a "emptyCount+=1"
::       )
::   )
::   
::   :: 清理临时文件
::   del userlist.tmp 2>nul
::   del users.txt 2>nul
::   
::   echo.
::   if %emptyCount% equ 0 (
::       echo 未发现空密码账户。
::   ) else (
::       echo 警告: 系统中存在 %emptyCount% 个空密码账户!
::       echo 建议立即为这些账户设置强密码以增强系统安全性。
::   )


echo （6）设置密码过期前提示天数, 密码到期14天前提示用户更改.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Policy" /v "PasswordExpiryWarning" /t REG_DWORD /d 0x0000000e /f

echo （7）设置屏幕保护程序 - 使用默认的(无)屏幕保护程序，时间设为15分钟,启用恢复时显示登录屏幕
:: 设置屏幕保护程序为默认(无)...
reg add "HKCU\Control Panel\Desktop" /v "ScreenSaveActive" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Desktop" /v "SCRNSAVE.EXE" /t REG_SZ /d "" /f

:: 设置屏幕保护等待时间为15分钟(900秒)
echo 设置屏幕保护等待时间为15分钟...
reg add "HKCU\Control Panel\Desktop" /v "ScreenSaveTimeOut" /t REG_SZ /d "900" /f

:: 启用恢复时显示登录屏幕(密码保护)
echo 启用恢复时显示登录屏幕...
reg add "HKCU\Control Panel\Desktop" /v "ScreenSaverIsSecure" /t REG_SZ /d "1" /f

echo （8） 设置服务器在暂停会话前所需的空闲时间为15分钟...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "AutoDisconnect" /t REG_DWORD /d 15 /f

echo （9）禁用Guest账户
net user guest /active:no

echo （10）限制匿名用户连接权限，防止枚举本地帐号和共享...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "RestrictAnonymous" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "RestrictAnonymousSAM" /t REG_DWORD /d 1 /f

::  echo（11）检查共享文件夹的权限设置是否安全
::  :: 创建临时文件存储共享列表
::  set "tempShareList=%temp%\share_list.tmp"
::  set "tempEveryoneShares=%temp%\everyone_shares.tmp"
::  del /f /q %tempShareList% 2>nul
::  del /f /q %tempEveryoneShares% 2>nul
::  
::  :: 获取所有共享文件夹列表
::  net share > %tempShareList%
::  
::  :: 标记共享列表开始行
::  set "shareListStarted="
::  set "everyoneShareCount=0"
::  
::  :: 遍历共享列表并检查每个共享的权限
::  for /f "tokens=*" %%a in (%tempShareList%) do (
::      set "line=%%a"
::      
::      :: 检测共享列表开始行（包含"--------"的行之后）
::      if defined shareListStarted (
::          :: 提取共享名（每行第一个空格前的部分）
::          for /f "tokens=1" %%s in ("!line!") do (
::              set "sharename=%%s"
::              
::              :: 排除已知的系统共享
::              if /i not "!sharename!"=="ADMIN$" (
::                  if /i not "!sharename!"=="C$" (
::                      if /i not "!sharename!"=="D$" (
::                          if /i not "!sharename!"=="IPC$" (
::                              if /i not "!sharename!"=="PRINT$" (
::                                  :: 检查共享权限是否包含Everyone
::                                  echo 检查共享: !sharename!
::                                  net share !sharename! | findstr /i /c:"Everyone" >nul
::                                  if !errorlevel! equ 0 (
::                                      echo 发现包含'Everyone'权限的共享: !sharename!
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
::  :: 输出结果
::  echo.
::  if %everyoneShareCount% gtr 0 (
::      echo 共发现 %everyoneShareCount% 个包含'Everyone'共享权限的文件夹。
::      echo 包含'Everyone'权限的共享列表已保存到: %tempEveryoneShares%
::      echo.
::      echo 建议操作:
::      echo 1. 检查列表中的共享文件夹，确认是否需要公开访问
::      echo 2. 对不需要公开访问的共享，使用以下命令修改权限:
::      echo    net share 共享名 /grant:用户名,权限
::      echo    (例如: net share MyDocs /grant:Users,Read)
::  ) else (
::      echo 未发现包含'Everyone'共享权限的文件夹。
::  )

echo (12) 配置不显示登录屏幕上的最后一个用户名...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "DontDisplayLastUserName" /t REG_DWORD /d 1 /f

echo (13) 开启源路由攻击保护...
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableIPSourceRouting" /t REG_DWORD /d 2 /f

echo （14）开启SYN攻击保护...
:: 启用SYN攻击保护
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v SynAttackProtect /t REG_DWORD /d 2 /f

:: 调整半连接队列大小
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpMaxHalfOpen /t REG_DWORD /d 1000 /f

:: 调整半连接请求最大值
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpMaxHalfOpenRetried /t REG_DWORD /d 800 /f

:: 减少SYN-ACK重试次数
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpMaxPortsExhausted /t REG_DWORD /d 5 /f

:: 设置SYN Cookie保护
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpTimedWaitDelay /t REG_DWORD /d 30 /f

echo (15)  限制ICMP回应请求(防止Ping Flood)...
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnableICMPRedirect /t REG_DWORD /d 0 /f

echo (16) 禁用失效网关检测...
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnableDeadGWDetect /t REG_DWORD /d 0 /f

echo (17) 禁用路由发现功能...
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnableRouterDiscovery /t REG_DWORD /d 0 /f

echo (18) 启用tcp碎片防护...
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnablePMTUDiscovery /t REG_DWORD /d 1 /f

echo (19) 禁用Windows硬盘默认共享...
:: 禁用自动共享管理$
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareServer /t REG_DWORD /d 0 /f
:: 禁用ADMIN$共享
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareWks /t REG_DWORD /d 0 /f
:: 禁用IPC$共享
sc config lanmanserver start=disabled >nul 2>&1


echo （20）禁用Windows自动登录...
:: 清除自动登录信息
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName /f >nul 2>&1
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword /f >nul 2>&1
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /f >nul 2>&1

:: 设置AutoAdminLogon为0（禁用自动登录）
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_SZ /d "0" /f

echo （21）禁用Simple TCP/IP服务(如果存在)
sc config stisvc start=disabled >nul 2>&1
sc stop stisvc >nul 2>&1

echo （22）禁用SMTP服务(如果存在)
sc config SMTPSVC start=disabled >nul 2>&1
sc stop SMTPSVC >nul 2>&1

echo （23）禁用WINS服务(如果存在)
sc config Wins start=disabled >nul 2>&1
sc stop Wins >nul 2>&1


echo （24）禁用DHCP Server服务
sc config DHCPServer start=disabled >nul 2>&1
sc stop DHCPServer >nul 2>&1


echo （25）禁用Message Queuing服务
sc config MSMQ start=disabled >nul 2>&1
sc stop MSMQ >nul 2>&1


echo （26）禁用SMB服务（SMB服务器不适用）
:: 禁用SMB1客户端和服务器组件
dism /online /disable-feature /featurename:SMB1Protocol-Client /norestart >nul 2>&1
dism /online /disable-feature /featurename:SMB1Protocol-Server /norestart >nul 2>&1

:: 禁用SMB2/3客户端和服务器组件
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB2 /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v SMB2 /t REG_DWORD /d 0 /f >nul 2>&1

:: 停止并禁用SMB服务
sc config LanmanServer start=disabled >nul 2>&1
sc config LanmanWorkstation start=disabled >nul 2>&1
sc stop LanmanServer /y >nul 2>&1
sc stop LanmanWorkstation /y >nul 2>&1
echo SMB服务已禁用!

echo （27）配置完整的审核策略，启用本地策略中审核策略中如下项。每项都需要设置为“成功”和“失败”都要审核
echo [version] >audit.inf
echo signature="$CHICAGO$" >>audit.inf
echo [Event Audit] >>audit.inf
echo 开启审核对象访问
echo AuditObjectAccess= 3 >>audit.inf
echo 开启审核特权使用
echo AuditPrivilegeUse= 3 >>audit.inf
echo 开启审核系统事件
echo AuditSystemEvents=3 >>audit.inf
echo 开启审核进程跟踪
echo AuditProcessTracking=3 >>audit.inf
echo 开启审核策略更改
echo AuditPolicyChange=3 >>audit.inf
echo 开启审核目录服务访问
echo AuditDSAccess=3 >>audit.inf
echo 开启审核帐户管理
echo AuditAccountManage=3 >>audit.inf
echo 开启审核帐户登陆事件
echo AuditAccountLogon=3 >>audit.inf
echo 开启审核登陆事件
echo AuditLogonEvents=3 >>audit.inf
echo gpupdate /force
secedit /configure /db audit.sdb /cfg audit.inf /log audit.log /quiet
del audit.*

echo （28）启用并正确配置Windows网络时间同步服务
echo 正在启动Windows Time服务...
net start w32time
echo 检查服务状态:
sc query w32time | findstr /i "STATE"


echo （29）检查是否安装的防病毒软件:
wmic /namespace:\\root\SecurityCenter2 path AntiVirusProduct get displayName, productState /format:list 2>nul
echo 检查结果:
set "found=0"
for /f "tokens=*" %%a in ('wmic /namespace:\\root\SecurityCenter2 path AntiVirusProduct get displayName 2^>nul') do (
    if not "%%a"=="" (
        if not "%%a"=="DisplayName" (
            set "found=1"
        )
    )
)
if %found%==1 (
    echo 系统中已安装防病毒软件。
) else (
    echo 未检测到防病毒软件安装!
    echo 建议立即安装并启用防病毒软件以保护系统安全。
)

:end
echo.
echo 注意：部分更改可能需要重新启动计算机才能完全生效。
echo 脚本执行完毕。按任意键退出...
pause >nul    