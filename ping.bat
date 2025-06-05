@echo off
setlocal enabledelayedexpansion
echo 开始批量ping指定IP列表...
echo 结果将保存到 ping_results.txt
echo. > ping_results.txt

set "ip_list=ip_list.txt"  REM 修改为你的IP列表文件路径

if not exist %ip_list% (
    echo 错误：找不到IP列表文件 %ip_list%
    pause
    exit /b
)

for /f "tokens=*" %%i in (%ip_list%) do (
    set "ip=%%i"
    echo 正在ping !ip! ...
    ping -n 1 -w 1000 !ip! | find "TTL=" > nul
    if errorlevel 1 (
        echo !ip! 不可达 >> ping_results.txt
    ) else (
        echo !ip! 可达 >> ping_results.txt
    )
)

echo 批量ping完成！结果已保存到 ping_results.txt
pause
