@echo off
setlocal enabledelayedexpansion
echo ��ʼ����pingָ��IP�б�...
echo ��������浽 ping_results.txt
echo. > ping_results.txt

set "ip_list=ip_list.txt"  REM �޸�Ϊ���IP�б��ļ�·��

if not exist %ip_list% (
    echo �����Ҳ���IP�б��ļ� %ip_list%
    pause
    exit /b
)

for /f "tokens=*" %%i in (%ip_list%) do (
    set "ip=%%i"
    echo ����ping !ip! ...
    ping -n 1 -w 1000 !ip! | find "TTL=" > nul
    if errorlevel 1 (
        echo !ip! ���ɴ� >> ping_results.txt
    ) else (
        echo !ip! �ɴ� >> ping_results.txt
    )
)

echo ����ping��ɣ�����ѱ��浽 ping_results.txt
pause
