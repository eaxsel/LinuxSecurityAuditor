#!/bin/bash
set -eo pipefail

if [[ $(uname) = "Linux" ]]; then
    os="\e[37mLinux\e[0m"
    IDLIKE=$(grep "ID_LIKE*" /etc/os-release | awk -F= '{print $2}')
    ID=$(grep "ID=*" /etc/os-release | awk -F= '{print $2}' | sed -n '2p')
    VERSION=$(grep "VERSION_ID=" /etc/os-release | awk -F= '{print $2}' | tr -d '"')
    if [[ $(grep "IMAGE_ID=" /etc/os-release) == *live  ]]; then 
        type="live"
    else    
        type="workspace"
    fi
else
    os="Windows"
fi
#echo $os #dlya testa vernocti systemi

if [[ -n $1 ]]; then 
    arg1=$1
fi


if [[ $EUID != 0 ]]; then
    echo -e "Please run the script with root privileges to get more accurate results and recommendations."
    exit 0
fi




function Linux {
    dater=$(date +"%Y %m %d" | tr ' ' '-'.txt)
    save=$(cd ~ && pwd)
    score="0"
    echo "--------------------------------------------"
    echo -e "[+]        \033[1mStart analysing sysyem\033[0m          |"
    echo "--------------------------------------------"
    echo -e "OS: \t \t [\e[36m${os}\e[0m]"
    echo -e "Family: \t [$IDLIKE]"
    echo -e "ID: \t \t [$ID]"
    echo -e "Release: \t [$VERSION]"
    echo -e "Type: \t \t [$type]\n"

    # reshit' problemu s failom kotorogo net
    located=$(locate -b '\reference_scan' | head -n 1) 
    locate -b '\213A.txt' > /dev/null 2>&1 && located_file="\e[32mFOUND\e[0m"  || located_file="\e[33mNOT FOUND\e[0m"
    echo -e "DUMP file: \t [$located_file]"
    if [[ -s "/var/log/clamav/last_scan.log" ]]; then
        log="\e[32mFOUND\e[0m"
    else    
        log="\e[33mNOT FOUND\e[0m"
    fi 
    echo ""

    function PC {
        model=$(grep -E "model name" /proc/cpuinfo | uniq | awk '{$1=$2=$3=""; sub(/^[ \t]+/, ""); print}' )
        grep -Eoq "nx|xd" /proc/cpuinfo && nx="\e[32mYES\e[0m" || { nx="\e[33mNO\e[0m"; echo -e "\e[33m#\e[0m The processor doesn't support NX/XD, but it's no good."; }
        grep -Eoq "smep" /proc/cpuinfo && smep="\e[32mYES\e[0m" || { smep="\e[33mNO\e[0m"; echo -e "\e[33m#\e[0m The processor doesn't support SMEP, but it's no good."; }
        grep -Eoq "smap" /proc/cpuinfo && smap="\e[32mYES\e[0m" || { smap="\e[33mNO\e[0m";  echo -e "\e[33m#\e[0m The processor doesn't support SMAP, but it's no good."; }
        grep -Eoq "avx" /proc/cpuinfo && AVX="\e[32mYES\e[0m" || { AVX="\e[33mNO\e[0m"; echo -e "\e[33m#\e[0m The processor doesn't support AVX, but it's not critical."; }
        grep -Eoq "avx512" /proc/cpuinfo && AVX512="\e[32mYES\e[0m" || { AVX512="\e[33mNO\e[0m"; echo -e "\e[33m#\e[0m The processor doesn't support AVX512, but it's not critical."; }
        grep -Eoq "sse4_2" /proc/cpuinfo && sse="\e[32mYES\e[0m" || { sse="\e[33mNO\e[0m"; echo -e "\e[33m#\e[0m The processor doesn't support SSE4.2, but it's not critical."; }
        grep -Eoq "aes" /proc/cpuinfo && aes="\e[32mYES\e[0m" || { aes="\e[33mNO\e[0m"; echo -e "\e[33m#\e[0m The processor doesn't support AES, but it's not critical."; }
        grep -Eoq "sha" /proc/cpuinfo && sha="\e[32mYES\e[0m" || { sha="\e[33mNO\e[0m"; echo -e "\e[33m#\e[0mThe processor doesn't support SHA, but it's not critical."; }

        #free=$(df /dev/sda1 | tail -1 | awk '{print $5}')
        dev=$(findmnt | sed '1d' | head -n 1 | awk '{print $2}')
        free=$(df "$dev" | tail -1 | awk '{print $5}')
        if [[ ${free%?} -gt 90 ]]; then
            free2="\033[33mLow\033[0m"
            echo -e "\e[33m#\e[0m Free space is low, you have only $free free space on your disk, please check your disk usage and free some space if needed"

        else
            free2="\e[32mOK\e[0m"
            (( score = score + 2 ))
        fi

        mem=$(grep MemAvailable /proc/meminfo | awk '{print $2}')
        let memfree=$mem/1024
        if [[ $memfree -lt 1024 ]]; then
            mems="\033[33mWarning\033[0m"
            echo -e "\e[33m#\e[0m Free memory is low, you have only $memfree MB free memory, please check your memory usage and close some applications if needed"

        else
            mems="\e[32mOK\e[0m"
            (( score = score + 2 ))
        fi

    }


    function net {
        ping -c 1 -W 2 8.8.8.8 &> /dev/null && net="\e[32mComplete\e[0m" || net="\e[33mNo\e[0m"

        if [[ $net == "Complete" ]]; then
            (( score = score + 5 ))
        fi

        google_date_raw=$(curl -sI \
        --max-time 5 \
        --connect-timeout 3 \
        --ipv4 \
        https://1.1.1.1 2>/dev/null \
        | grep -i '^Date:' \
        | cut -d' ' -f2-)

        
        if [[ -n "$google_date_raw" ]]; then

            google_ts=$(LC_ALL=C date -u -d "$google_date_raw" +%s 2>/dev/null)

            if [[ -n "$google_ts" ]]; then

                google_time=$(TZ=Europe/Moscow date -d "@$google_ts" +"%H:%M")
                local_time=$(date +"%H:%M")

                if [[ "$google_time" == "$local_time" ]]; then
                act="\e[32mActual\e[0m"
                (( score = score + 2 ))
                else
                act="\e[33mNot Actual\e[0m"
                echo -e "\e[33m#\e[0m System time is not actual (MSK: $google_time, System: $local_time)"
                fi


            else
                act="\e[33mNot Actual\e[0m"
                echo -e "\e[33m#\e[0m Failed to parse Google date"

            fi

        else
            act="\e[33mNot internet for check\e[0m"
            echo -e "\e[33m#\e[0m System time is not actual, but you have no internet connection for check"

        fi  


        if command -v ufw &> /dev/null; then
            ufw="\e[32mInstalled\e[0m"
            (( score = score + 8 ))
        else
            ufw="\e[31mNot installed\e[0m"
            echo -e "\e[33m#\e[0m UFW is not installed, you can install it with 'sudo apt install ufw' and then enable it with 'sudo ufw enable'"

        fi

        if ip a | grep tun &> /dev/null; then
            vpn="\e[32mActive\e[0m"
            (( score = score + 5 ))
        else
            vpn="\e[33mNot active\e[0m"
            echo -e "\e[33m#\e[0m VPN is not active, you can use OpenVPN or WireGuard for secure connection to the internet"

        fi

        cp /etc/resolv.conf /tmp/tmpfile.txt
        arrdns=()
        while IFS= read line; do
            if [[ $line == *"8.8.8.8"*  || $line == *"8.8.4.4"* ]];then
                arrdns+=("($line is Google Dns)")
                (( score = score + 4 ))
            elif [[ $line == *"1.1.1.1"*  || $line == *"1.0.0.1"* ]]; then
                arrdns+=("($line is Cloudflare DNS)")
                (( score = score + 3 ))
            elif [[ $line == *"10.0"*  || $line ==  *"192.168.0."* ]]; then
                arrdns+=("($line is local)")
            elif [[ "$line" =~ ^nameserver[[:space:]]+fd ]]; then
                arrdns+=("($line is local)")
            else
                arrdns+=("($line is Warning)")
                (( score = score - 2 ))
                echo -e "\e[33m#\e[0m Warning: Unusual DNS server found: $line. Please check your DNS settings and ensure that you are using a trusted DNS server."

            fi
        done < <(sed '1d' /etc/resolv.conf)

        ports="\e[32mGood\e[0m"
        risky_ports=(21 23 445)
        for port in "${risky_ports[@]}"; do
            if sudo ss -tulpn | grep -q ":$port "; then
                echo -e "\e[33m#\e[0m Warning: Risky port $port is open. Please check which service is using this port and consider closing it if it's not necessary."
                ports="\e[31mWarning\e[0m"
            fi

        done

        if [[ $net == "Complete" ]]; then
            stable=$(apt-get upgrade -s | grep -P '^Inst' | wc -l)
            if [[ "$stable" -eq 0 ]]; then
                update="\e[32mOK\e[0m"
            #(( score = score + 10 ))
            else
                update="\e[33mNeed update\e[0m"
                echo -e "\e[33m#\e[0m There are $stable updates available for your system. Please run 'sudo apt update && sudo apt upgrade' to keep your system secure and up to date."

                fi
            else 
                update="\e[33mNo internet\e[0m"
        fi

    }

    function RWXAUDIT {
       
        # =================home
        if [[ $(stat -c "%a" "/home") == 755 ]]; then
            stat1="\e[32m$(stat -c "%a" "/home")\e[0m"
            (( score = score + 8 ))
        else
            stat1="\e[31m$(stat -c "%a" "/home")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /home has permissions $(stat -c "%a" "/home"), it should be 755. Please change the permissions with 'sudo chmod 755 /home'"

        fi
        if [[ $(stat -c "%U:%G" "/home") == "root:root" ]]; then
            owner1="\e[32m$(stat -c "%U:%G" "/home")\e[0m"
            (( score = score + 8 ))
        else
            owner1="\e[31m$(stat -c "%U:%G" "/home")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /home is owned by $(stat -c "%U:%G" "/home"), it should be root:root. Please change the ownership with 'sudo chown root:root /home'"

        fi

        # =============root
        if [[ $(stat -c "%a" "/root") == 700 ]]; then
            stat2="\e[32m$(stat -c "%a" "/root")\e[0m"
            (( score = score + 10 ))
        else
            stat2="\e[31m$(stat -c "%a" "/root")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /root has permissions $(stat -c "%a" "/root"), it should be 700. Please change the permissions with 'sudo chmod 700 /root'"

        fi
        if [[ $(stat -c "%U:%G" "/root") == "root:root" ]]; then
            owner2="\e[32m$(stat -c "%U:%G" "/root")\e[0m"
            (( score = score + 8 ))
        else
            owner2="\e[31m$(stat -c "%U:%G" "/root")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /root is owned by $(stat -c "%U:%G" "/root"), it should be root:root. Please change the ownership with 'sudo chown root:root /root'"

        fi

        #================= boot 
        if [[ $(stat -c "%a" "/boot") == 755 ]]; then
            stat3="\e[32m$(stat -c "%a" "/boot")\e[0m"
            (( score = score + 8 ))
        else
            stat3="\e[31m$(stat -c "%a" "/boot")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /boot has permissions $(stat -c "%a" "/boot"), it should be 755. Please change the permissions with 'sudo chmod 755 /boot'"

        fi
        if [[ $(stat -c "%U:%G" "/boot") == "root:root" ]]; then
            owner3="\e[32m$(stat -c "%U:%G" "/boot")\e[0m"
            (( score = score + 8 ))
        else
            owner3="\e[31m$(stat -c "%U:%G" "/boot")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /boot is owned by $(stat -c "%U:%G" "/boot"), it should be root:root. Please change the ownership with 'sudo chown root:root /boot'"

        fi

        # ==============/boot/grub/grub.cfg 
        if [[ ! -f /boot/grub/grub.cfg ]]; then
            stat4="N/A"
            owner4="N/A"
        else
            if [[ $(stat -c "%a" "/boot/grub/grub.cfg") == 600 ]]; then
                stat4="\e[32m$(stat -c "%a" "/boot/grub/grub.cfg")\e[0m"
                (( score = score + 10 ))
            else
                stat4="\e[31m$(stat -c "%a" "/boot/grub/grub.cfg")\e[0m"
                (( score = score + 5 ))
                echo -e "\e[33m#\e[0m Warning: /boot/grub/grub.cfg has permissions $(stat -c "%a" "/boot/grub/grub.cfg"), it should be 600. Please change the permissions with 'sudo chmod 600 /boot/grub/grub.cfg'"

            fi
            if [[ $(stat -c "%U:%G" "/boot/grub/grub.cfg") == "root:root" ]]; then
                owner4="\e[32m$(stat -c "%U:%G" "/boot/grub/grub.cfg")\e[0m"
                (( score = score + 8 ))
            else
                owner4="\e[31m$(stat -c "%U:%G" "/boot/grub/grub.cfg")\e[0m"
                (( score = score + 5 ))
                echo -e "\e[33m#\e[0m Warning: /boot/grub/grub.cfg is owned by $(stat -c "%U:%G" "/boot/grub/grub.cfg"), it should be root:root. Please change the ownership with 'sudo chown root:root /boot/grub/grub.cfg'"

            fi
        fi

        #===================== fstab
        if [[ $(stat -c "%a" "/etc/fstab") == 644 ]]; then
            stat5="\e[33m$(stat -c "%a" "/etc/fstab")\e[0m"
            (( score = score + 8 ))
            echo -e "\e[33m#\e[0m Recommended permissions for /etc/fstab is 640"

        elif [[ $(stat -c "%a" "/etc/fstab") == 600 ]]; then
            stat5="\e[32m$(stat -c "%a" "/etc/fstab")\e[0m"
            (( score = score + 8 ))
        else
            stat5="\e[31m$(stat -c "%a" "/etc/fstab")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/fstab has permissions $(stat -c "%a" "/etc/fstab"), it should be 644. Please change the permissions with 'sudo chmod 644 /etc/fstab'"

        fi
        if [[ $(stat -c "%U:%G" "/etc/fstab") == "root:root" ]]; then
            owner5="\e[32m$(stat -c "%U:%G" "/etc/fstab")\e[0m"
            (( score = score + 8 ))
        else
            owner5="\e[31m$(stat -c "%U:%G" "/etc/fstab")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/fstab is owned by $(stat -c "%U:%G" "/etc/fstab"), it should be root:root. Please change the ownership with 'sudo chown root:root /etc/fstab'"

        fi

        #================== hosts
        if [[ $(stat -c "%a" "/etc/hosts") == 644 ]]; then
            stat6="\e[33m$(stat -c "%a" "/etc/hosts")\e[0m"
            (( score = score + 8 ))
            echo -e "\e[33m#\e[0m Recommended permissions for /etc/hosts is 640"
        elif [[ $(stat -c "%a" "/etc/hosts") == 600 ]]; then
            stat6="\e[32m$(stat -c "%a" "/etc/hosts")\e[0m"
            (( score = score + 8 ))
        else
            stat6="\e[31m$(stat -c "%a" "/etc/hosts")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/hosts has permissions $(stat -c "%a" "/etc/hosts"), it should be 644. Please change the permissions with 'sudo chmod 644 /etc/hosts'"

        fi
        if [[ $(stat -c "%U:%G" "/etc/hosts") == "root:root" ]]; then
            owner6="\e[32m$(stat -c "%U:%G" "/etc/hosts")\e[0m"
            (( score = score + 8 ))
        else
            owner6="\e[31m$(stat -c "%U:%G" "/etc/hosts")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/hosts is owned by $(stat -c "%U:%G" "/etc/hosts"), it should be root:root. Please change the ownership with 'sudo chown root:root /etc/hosts'"

        fi

        #================== passwd
        if [[ $(stat -c "%a" "/etc/passwd") == 644 ]]; then
            stat7="\e[32m$(stat -c "%a" "/etc/passwd")\e[0m"
            (( score = score + 8 ))
        else
            stat7="\e[31m$(stat -c "%a" "/etc/passwd")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/passwd has permissions $(stat -c "%a" "/etc/passwd"), it should be 644. Please change the permissions with 'sudo chmod 644 /etc/passwd'"

        fi
        if [[ $(stat -c "%U:%G" "/etc/passwd") == "root:root" ]]; then
            owner7="\e[32m$(stat -c "%U:%G" "/etc/passwd")\e[0m"
            (( score = score + 8 ))
        else
            owner7="\e[31m$(stat -c "%U:%G" "/etc/passwd")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/passwd is owned by $(stat -c "%U:%G" "/etc/passwd"), it should be root:root. Please change the ownership with 'sudo chown root:root /etc/passwd'"

        fi

        #================== shadow
        if [[ $(stat -c "%a" "/etc/shadow") =~ (640|600) ]]; then
            stat8="\e[32m$(stat -c "%a" "/etc/shadow")\e[0m"
            (( score = score + 15 ))
        else
            stat8="\e[31m$(stat -c "%a" "/etc/shadow")\e[0m"
            echo -e "\e[33m#\e[0m Warning: /etc/shadow has permissions $(stat -c "%a" "/etc/shadow"), it should be 640 or 600. Please change the permissions with 'sudo chmod 640 /etc/shadow'"

        fi
        if [[ $(stat -c "%U:%G" "/etc/shadow") == "root:shadow" ]]; then
            owner8="\e[32m$(stat -c "%U:%G" "/etc/shadow")\e[0m"
            (( score = score + 15 ))
        else
            owner8="\e[31m$(stat -c "%U:%G" "/etc/shadow")\e[0m"
            echo -e "\e[33m#\e[0m Warning: /etc/shadow is owned by $(stat -c "%U:%G" "/etc/shadow"), it should be root:shadow. Please change the ownership with 'sudo chown root:shadow /etc/shadow'"

        fi

        #================ group
        if [[ $(stat -c "%a" "/etc/group") == 644 ]]; then
            stat9="\e[33m$(stat -c "%a" "/etc/group")\e[0m"
            (( score = score + 8 ))
            echo -e "\e[33m#\e[0m Recommended permissions for /etc/group is 640"
        elif [[ $(stat -c "%a" "/etc/group") == 600 ]]; then
            stat9="\e[32m$(stat -c "%a" "/etc/group")\e[0m"
            (( score = score + 8 ))
        else
            stat9="\e[31m$(stat -c "%a" "/etc/group")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/group has permissions $(stat -c "%a" "/etc/group"), it should be 644. Please change the permissions with 'sudo chmod 644 /etc/group'"
        fi
        if [[ $(stat -c "%U:%G" "/etc/group") == "root:root" ]]; then
            owner9="\e[32m$(stat -c "%U:%G" "/etc/group")\e[0m"
            (( score = score + 8 ))
        else
            owner9="\e[31m$(stat -c "%U:%G" "/etc/group")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/group is owned by $(stat -c "%U:%G" "/etc/group"), it should be root:root. Please change the ownership with 'sudo chown root:root /etc/group'"
        fi


        #===================== gshadow
        if [[ $(stat -c "%a" "/etc/gshadow") == 640 ]]; then
            stat10="\e[32m$(stat -c "%a" "/etc/gshadow")\e[0m"
            (( score = score + 10 ))
        else
            stat10="\e[31m$(stat -c "%a" "/etc/gshadow")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/gshadow has permissions $(stat -c "%a" "/etc/gshadow"), it should be 640. Please change the permissions with 'sudo chmod 640 /etc/gshadow'"

        fi
        if [[ $(stat -c "%U:%G" "/etc/gshadow") == "root:shadow" ]]; then
            owner10="\e[32m$(stat -c "%U:%G" "/etc/gshadow")\e[0m"
            (( score = score + 8 ))
        else
            owner10="\e[31m$(stat -c "%U:%G" "/etc/gshadow")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/gshadow is owned by $(stat -c "%U:%G" "/etc/gshadow"), it should be root:root. Please change the ownership with 'sudo chown root:root /etc/gshadow'"

        fi

        # ================/etc/login.defs
        if [[ $(stat -c "%a" "/etc/login.defs") == 644 ]]; then
            stat11="\e[33m$(stat -c "%a" "/etc/login.defs")\e[0m"
            (( score = score + 8 ))
            echo -e "\e[33m#\e[0m Recommended permissions for /etc/login.defs is 640"
        elif [[ $(stat -c "%a" "/etc/login.defs") == 600 ]]; then
            stat11="\e[32m$(stat -c "%a" "/etc/login.defs")\e[0m"
            (( score = score + 8 ))
        else
            stat11="\e[31m$(stat -c "%a" "/etc/login.defs")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/login.defs has permissions $(stat -c "%a" "/etc/login.defs"), it should be 644. Please change the permissions with 'sudo chmod 644 /etc/login.defs'"

        fi
        if [[ $(stat -c "%U:%G" "/etc/login.defs") == "root:root" ]]; then
            owner11="\e[32m$(stat -c "%U:%G" "/etc/login.defs")\e[0m"
            (( score = score + 8 ))
        else
            owner11="\e[31m$(stat -c "%U:%G" "/etc/login.defs")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/login.defs is owned by $(stat -c "%U:%G" "/etc/login.defs"), it should be root:root. Please change the ownership with 'sudo chown root:root /etc/login.defs'"

        fi
        #======================= /etc/shells 
        if [[ $(stat -c "%a" "/etc/shells") == 644 ]]; then
            stat12="\e[32m$(stat -c "%a" "/etc/shells")\e[0m"
            (( score = score + 8 ))
        else
            stat12="\e[31m$(stat -c "%a" "/etc/shells")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/shells has permissions $(stat -c "%a" "/etc/shells"), it should be 644. Please change the permissions with 'sudo chmod 644 /etc/shells'"

        fi
        if [[ $(stat -c "%U:%G" "/etc/shells") == "root:root" ]]; then
            owner12="\e[32m$(stat -c "%U:%G" "/etc/shells")\e[0m"
            (( score = score + 8 ))
        else
            owner12="\e[31m$(stat -c "%U:%G" "/etc/shells")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/shells is owned by $(stat -c "%U:%G" "/etc/shells"), it should be root:root. Please change the ownership with 'sudo chown root:root /etc/shells'"

        fi


        # =====================/etc/sudoers
        if [[ $(stat -c "%a" "/etc/sudoers") =~ (440) ]]; then
            stat13="\e[32m$(stat -c "%a" "/etc/sudoers")\e[0m"
            (( score = score + 12 ))
        else
            stat13="\e[31m$(stat -c "%a" "/etc/sudoers")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/sudoers has permissions $(stat -c "%a" "/etc/sudoers"), it should be 440. Please change the permissions with 'sudo chmod 440 /etc/sudoers'"

        fi
        if [[ $(stat -c "%U:%G" "/etc/sudoers") == "root:root" ]]; then
            owner13="\e[32m$(stat -c "%U:%G" "/etc/sudoers")\e[0m"
            (( score = score + 12 ))
        else
            owner13="\e[31m$(stat -c "%U:%G" "/etc/sudoers")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/sudoers is owned by $(stat -c "%U:%G" "/etc/sudoers"), it should be root:root. Please change the ownership with 'sudo chown root:root /etc/sudoers'"

        fi

        # =====================/etc/sudoers.d/
        if [[ $(stat -c "%a" "/etc/sudoers.d/") == 750 ]]; then
            stat14="\e[32m$(stat -c "%a" "/etc/sudoers.d/")\e[0m"
            (( score = score + 10 ))
        else
            stat14="\e[31m$(stat -c "%a" "/etc/sudoers.d/")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/sudoers.d/ has permissions $(stat -c "%a" "/etc/sudoers.d/"), it should be 750. Please change the permissions with 'sudo chmod 750 /etc/sudoers.d/'"

        fi
        if [[ $(stat -c "%U:%G" "/etc/sudoers.d/") == "root:root" ]]; then
            owner14="\e[32m$(stat -c "%U:%G" "/etc/sudoers.d/")\e[0m"
            (( score = score + 10 ))
        else
            owner14="\e[31m$(stat -c "%U:%G" "/etc/sudoers.d/")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/sudoers.d/ is owned by $(stat -c "%U:%G" "/etc/sudoers.d/"), it should be root:root. Please change the ownership with 'sudo chown root:root /etc/sudoers.d/'"

        fi

        #====================== etc/pam.d
        if [[ $(stat -c "%a" "/etc/pam.d/") == 755 ]]; then
            stat15="\e[32m$(stat -c "%a" "/etc/pam.d/")\e[0m"
            (( score = score + 10 ))
        else
            stat15="\e[31m$(stat -c "%a" "/etc/pam.d/")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/pam.d/ has permissions $(stat -c "%a" "/etc/pam.d/"), it should be 755. Please change the permissions with 'sudo chmod 755 /etc/pam.d/'"

        fi
        if [[ $(stat -c "%U:%G" "/etc/pam.d/") == "root:root" ]]; then
            owner15="\e[32m$(stat -c "%U:%G" "/etc/pam.d/")\e[0m"
            (( score = score + 10 ))
        else
            owner15="\e[31m$(stat -c "%U:%G" "/etc/pam.d/")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/pam.d/ is owned by $(stat -c "%U:%G" "/etc/pam.d/"), it should be root:root. Please change the ownership with 'sudo chown root:root /etc/pam.d/'"

        fi

        #======================= /etc/security
        if [[ $(stat -c "%a" "/etc/security/") == 755 ]]; then
            stat16="\e[32m$(stat -c "%a" "/etc/security/")\e[0m"
            (( score = score + 10 ))
        else
            stat16="\e[31m$(stat -c "%a" "/etc/security/")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/security/ has permissions $(stat -c "%a" "/etc/security/"), it should be 755. Please change the permissions with 'sudo chmod 755 /etc/security/'"

        fi
        if [[ $(stat -c "%U:%G" "/etc/security/") == "root:root" ]]; then
            owner16="\e[32m$(stat -c "%U:%G" "/etc/security/")\e[0m"
            (( score = score + 10 ))
        else
            owner16="\e[31m$(stat -c "%U:%G" "/etc/security/")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/security/ is owned by $(stat -c "%U:%G" "/etc/security/"), it should be root:root. Please change the ownership with 'sudo chown root:root /etc/security/'"

        fi
        # =======================/etc/ssh/sshd_config
        if [[ $(stat -c "%a" "/etc/ssh/sshd_config") == 600 ]]; then
            stat17="\e[32m$(stat -c "%a" "/etc/ssh/sshd_config")\e[0m"
            (( score = score + 10 ))
        else
            stat17="\e[31m$(stat -c "%a" "/etc/ssh/sshd_config")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/ssh/sshd_config has permissions $(stat -c "%a" "/etc/ssh/sshd_config"), it should be 600. Please change the permissions with 'sudo chmod 600 /etc/ssh/sshd_config'"

        fi
        if [[ $(stat -c "%U:%G" "/etc/ssh/sshd_config") == "root:root" ]]; then
            owner17="\e[32m$(stat -c "%U:%G" "/etc/ssh/sshd_config")\e[0m"
            (( score = score + 10 ))
        else
            owner17="\e[31m$(stat -c "%U:%G" "/etc/ssh/sshd_config")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/ssh/sshd_config is owned by $(stat -c "%U:%G" "/etc/ssh/sshd_config"), it should be root:root. Please change the ownership with 'sudo chown root:root /etc/ssh/sshd_config'"

        fi

        # ========================/etc/ssh/ssh_config
        if [[ $(stat -c "%a" "/etc/ssh/ssh_config") == 644 ]]; then
            stat18="\e[32m$(stat -c "%a" "/etc/ssh/ssh_config")\e[0m"
            (( score = score + 8 ))
        else
            stat18="\e[31m$(stat -c "%a" "/etc/ssh/ssh_config")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/ssh/ssh_config has permissions $(stat -c "%a" "/etc/ssh/ssh_config"), it should be 644. Please change the permissions with 'sudo chmod 644 /etc/ssh/ssh_config'"

        fi
        if [[ $(stat -c "%U:%G" "/etc/ssh/ssh_config") == "root:root" ]]; then
            owner18="\e[32m$(stat -c "%U:%G" "/etc/ssh/ssh_config")\e[0m"
            (( score = score + 8 ))
        else
            owner18="\e[31m$(stat -c "%U:%G" "/etc/ssh/ssh_config")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/ssh/ssh_config is owned by $(stat -c "%U:%G" "/etc/ssh/ssh_config"), it should be root:root. Please change the ownership with 'sudo chown root:root /etc/ssh/ssh_config'"

        fi
        
        #=========================== /root/.ssh/

        if [[ $(stat -c "%a" "/root/.ssh/") == 700 ]]; then
            stat19="\e[32m$(stat -c "%a" "/root/.ssh/")\e[0m"
            (( score = score + 10 ))
        else
            stat19="\e[31m$(stat -c "%a" "/root/.ssh/")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /root/.ssh/ has permissions $(stat -c "%a" "/root/.ssh/"), it should be 700. Please change the permissions with 'sudo chmod 700 /root/.ssh/'"

        fi
        if [[ $(stat -c "%U:%G" "/root/.ssh/") == "root:root" ]]; then
            owner19="\e[32m$(stat -c "%U:%G" "/root/.ssh/")\e[0m"
            (( score = score + 10 ))
        else
            owner19="\e[31m$(stat -c "%U:%G" "/root/.ssh/")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /root/.ssh/ is owned by $(stat -c "%U:%G" "/root/.ssh/"), it should be root:root. Please change the ownership with 'sudo chown root:root /root/.ssh/'"

        fi

        #=========================== /home/*/.ssh/
 


        #============================= /etc/profile
        if [[ $(stat -c "%a" "/etc/profile") == 644 ]]; then
            stat21="\e[32m$(stat -c "%a" "/etc/profile")\e[0m"
            (( score = score + 8 ))
        else
            stat21="\e[31m$(stat -c "%a" "/etc/profile")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/profile has permissions $(stat -c "%a" "/etc/profile"), it should be 644. Please change the permissions with 'sudo chmod 644 /etc/profile'"

        fi
        if [[ $(stat -c "%U:%G" "/etc/profile") == "root:root" ]]; then
            owner21="\e[32m$(stat -c "%U:%G" "/etc/profile")\e[0m"
            (( score = score + 8 ))
        else
            owner21="\e[31m$(stat -c "%U:%G" "/etc/profile")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/profile is owned by $(stat -c "%U:%G" "/etc/profile"), it should be root:root. Please change the ownership with 'sudo chown root:root /etc/profile'"
        fi
        #============================= /etc/bash.bashrc
        if [[ $(stat -c "%a" "/etc/bash.bashrc") == 644 ]]; then
            stat22="\e[32m$(stat -c "%a" "/etc/bash.bashrc")\e[0m"
            (( score = score + 8 ))
        else
            stat22="\e[31m$(stat -c "%a" "/etc/bash.bashrc")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/bash.bashrc has permissions $(stat -c "%a" "/etc/bash.bashrc"), it should be 644. Please change the permissions with 'sudo chmod 644 /etc/bash.bashrc'"
        fi
        if [[ $(stat -c "%U:%G" "/etc/bash.bashrc") == "root:root" ]]; then
            owner22="\e[32m$(stat -c "%U:%G" "/etc/bash.bashrc")\e[0m"
            (( score = score + 8 ))
        else
            owner22="\e[31m$(stat -c "%U:%G" "/etc/bash.bashrc")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/bash.bashrc is owned by $(stat -c "%U:%G" "/etc/bash.bashrc"), it should be root:root. Please change the ownership with 'sudo chown root:root /etc/bash.bashrc'"
        fi

        #============================= /etc/crontab
        if [[ $(stat -c "%a" "/etc/crontab") == 644 ]]; then
            stat23="\e[33m$(stat -c "%a" "/etc/crontab")\e[0m"
            (( score = score + 8 ))
        elif [[ $(stat -c "%a" "/etc/crontab") == 600 ]]; then
            stat23="\e[32m$(stat -c "%a" "/etc/crontab")\e[0m"
            (( score = score + 8 ))
            echo -e "\e[33m#\e[0m Recommended permissions for /etc/crontab is 644"
        else
            stat23="\e[31m$(stat -c "%a" "/etc/crontab")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/crontab has permissions $(stat -c "%a" "/etc/crontab"), it should be 644. Please change the permissions with 'sudo chmod 644 /etc/crontab'"
        fi
        if [[ $(stat -c "%U:%G" "/etc/crontab") == "root:root" ]]; then
            owner23="\e[32m$(stat -c "%U:%G" "/etc/crontab")\e[0m"
            (( score = score + 8 ))
        else
            owner23="\e[31m$(stat -c "%U:%G" "/etc/crontab")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/crontab is owned by $(stat -c "%U:%G" "/etc/crontab"), it should be root:root. Please change the ownership with 'sudo chown root:root /etc/crontab'"
        fi

         #========================== /etc/cron.d/ 
        
        if [[ $(stat -c "%a" "/etc/cron.d/") == 755 ]]; then
            stat24="\e[32m$(stat -c "%a" "/etc/cron.d/")\e[0m"
            (( score = score + 10 ))
        else
            stat24="\e[31m$(stat -c "%a" "/etc/cron.d/")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/cron.d/ has permissions $(stat -c "%a" "/etc/cron.d/"), it should be 755. Please change the permissions with 'sudo chmod 755 /etc/cron.d/'"

        fi
        if [[ $(stat -c "%U:%G" "/etc/cron.d/") == "root:root" ]]; then
            owner24="\e[32m$(stat -c "%U:%G" "/etc/cron.d/")\e[0m"
            (( score = score + 10 ))
        else
            owner24="\e[31m$(stat -c "%U:%G" "/etc/cron.d/")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/cron.d/ is owned by $(stat -c "%U:%G" "/etc/cron.d/"), it should be root:root. Please change the ownership with 'sudo chown root:root /etc/cron.d/'"

        fi

        #=============================== /etc/cron.daily/
        if [[ $(stat -c "%a" "/etc/cron.daily/") == 755 ]]; then
            stat25="\e[32m$(stat -c "%a" "/etc/cron.daily/")\e[0m"
            (( score = score + 10 ))
        else
            stat25="\e[31m$(stat -c "%a" "/etc/cron.daily/")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/cron.daily/ has permissions $(stat -c "%a" "/etc/cron.daily/"), it should be 755. Please change the permissions with 'sudo chmod 755 /etc/cron.daily/'"

        fi
        if [[ $(stat -c "%U:%G" "/etc/cron.daily/") == "root:root" ]]; then
            owner25="\e[32m$(stat -c "%U:%G" "/etc/cron.daily/")\e[0m"
            (( score = score + 10 ))
        else
            owner25="\e[31m$(stat -c "%U:%G" "/etc/cron.daily/")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/cron.daily/ is owned by $(stat -c "%U:%G" "/etc/cron.daily/"), it should be root:root. Please change the ownership with 'sudo chown root:root /etc/cron.daily/'"
        fi

         #=============================== /etc/cron.hourly/
        if [[ $(stat -c "%a" "/etc/cron.hourly/") == 755 ]]; then
            stat26="\e[32m$(stat -c "%a" "/etc/cron.hourly/")\e[0m"
            (( score = score + 10 ))
        else
            stat26="\e[31m$(stat -c "%a" "/etc/cron.hourly/")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/cron.hourly/ has permissions $(stat -c "%a" "/etc/cron.hourly/"), it should be 755. Please change the permissions with 'sudo chmod 755 /etc/cron.hourly/'"
        fi
        if [[ $(stat -c "%U:%G" "/etc/cron.hourly/") == "root:root" ]]; then
            owner26="\e[32m$(stat -c "%U:%G" "/etc/cron.hourly/")\e[0m"
            (( score = score + 10 ))
        else
            owner26="\e[31m$(stat -c "%U:%G" "/etc/cron.hourly/")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/cron.hourly/ is owned by $(stat -c "%U:%G" "/etc/cron.hourly/"), it should be root:root. Please change the ownership with 'sudo chown root:root /etc/cron.hourly/'"
        fi

        #========================= /etc/cron.monthly/
        if [[ $(stat -c "%a" "/etc/cron.monthly/") == 755 ]]; then
            stat27="\e[32m$(stat -c "%a" "/etc/cron.monthly/")\e[0m"
            (( score = score + 10 ))
        else
            stat27="\e[31m$(stat -c "%a" "/etc/cron monthly/")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc   /cron.monthly/ has permissions $(stat -c "%a" "/etc/cron.monthly/"), it should be 755. Please change the permissions with 'sudo chmod 755 /etc/cron.monthly/'"
        fi
        if [[ $(stat -c "%U:%G" "/etc/cron.monthly/") == "root:root" ]]; then
            owner27="\e[32m$(stat -c "%U:%G" "/etc/cron.monthly/")\e[0m"
            (( score = score + 10 ))
        else
            owner27="\e[31m$(stat -c "%U:%G" "/etc/cron.monthly/")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/cron.monthly/ is owned by $(stat -c "%U:%G" "/etc/cron.monthly/"), it should be root:root. Please change the ownership with 'sudo chown root:root /etc/cron.monthly/'"
        fi

        #============================== /etc/cron.weekly/
        if [[ $(stat -c "%a" "/etc/cron.weekly/") == 755 ]]; then
            stat28="\e[32m$(stat -c "%a" "/etc/cron.weekly/")\e[0m"
            (( score = score + 10 ))
        else
            stat28="\e[31m$(stat -c "%a" "/etc/cron.weekly/")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/cron.weekly/ has permissions $(stat -c "%a" "/etc/cron.weekly/"), it should be 755. Please change the permissions with 'sudo chmod 755 /etc/cron.weekly/'"

        fi
        if [[ $(stat -c "%U:%G" "/etc/cron.weekly/") == "root:root" ]]; then
            owner28="\e[32m$(stat -c "%U:%G" "/etc/cron.weekly/")\e[0m"
            (( score = score + 10 ))
        else
            owner28="\e[31m$(stat -c "%U:%G" "/etc/cron.weekly/")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/cron.weekly/ is owned by $(stat -c "%U:%G" "/etc/cron.weekly/"), it should be root:root. Please change the ownership with 'sudo chown root:root /etc/cron.weekly/'"
        fi

        #============================== /var/log/cron
    

        #============================= /etc/systemd/
        if [[ $(stat -c "%a" "/etc/systemd/") == 755 ]]; then
            stat30="\e[32m$(stat -c "%a" "/etc/systemd/")\e[0m"
            (( score = score + 10 ))
        else
            stat30="\e[31m$(stat -c "%a" "/etc/systemd/")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/systemd/ has permissions $(stat -c "%a" "/etc/systemd/"), it should be 755. Please change the permissions with 'sudo chmod 755 /etc/systemd/'"

        fi
        if [[ $(stat -c "%U:%G" "/etc/systemd/") == "root:root" ]]; then    
            owner30="\e[32m$(stat -c "%U:%G" "/etc/systemd/")\e[0m"
            (( score = score + 10 ))
        else
            owner30="\e[31m$(stat -c "%U:%G" "/etc/systemd/")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/systemd/ is owned by $(stat -c "%U:%G" "/etc/systemd/"), it should be root:root. Please change the ownership with 'sudo chown root:root /etc/systemd/'"

        fi

        #============================= /usr/lib/systemd/
        if [[ $(stat -c "%a" "/usr/lib/systemd/") == 755 ]]; then
            stat31="\e[32m$(stat -c "%a" "/usr/lib/systemd/")\e[0m"
            (( score = score + 10 ))
        else
            stat31="\e[31m$(stat -c "%a" "/usr/lib/systemd/")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /usr/lib/systemd/ has permissions $(stat -c "%a" "/usr/lib/systemd/"), it should be 755. Please change the permissions with 'sudo chmod 755 /usr/lib/systemd/'"

        fi
        if [[ $(stat -c "%U:%G" "/usr/lib/systemd/") == "root:root" ]]; then
            owner31="\e[32m$(stat -c "%U:%G" "/usr/lib/systemd/")\e[0m"
            (( score = score + 10 ))
        else
            owner31="\e[31m$(stat -c "%U:%G" "/usr/lib/systemd/")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /usr/lib/systemd/ is owned by $(stat -c "%U:%G" "/usr/lib/systemd/"), it should be root:root. Please change the ownership with 'sudo chown root:root /usr/lib/systemd/'"

        fi

        #======================== /lib/systemd/
        if [[ $(stat -c "%a" "/lib/systemd/") == 755 ]]; then
            stat32="\e[32m$(stat -c "%a" "/lib/systemd/")\e[0m"
            (( score = score + 10 ))
        else
            stat32="\e[31m$(stat -c "%a" "/lib/systemd/")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /lib/systemd/ has permissions $(stat -c "%a" "/lib/systemd/"), it should be 755. Please change the permissions with 'sudo chmod 755 /lib/systemd/'"
        fi
        if [[ $(stat -c "%U:%G" "/lib/systemd/") == "root:root" ]]; then
            owner32="\e[32m$(stat -c "%U:%G" "/lib/systemd/")\e[0m"
            (( score = score + 10 ))
        else
            owner32="\e[31m$(stat -c "%U:%G" "/lib/systemd/")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /lib/systemd/ is owned by $(stat -c "%U:%G" "/lib/systemd/"), it should be root:root. Please change the ownership with 'sudo chown root:root /lib/systemd/'"

        fi

        #=============================== /var/log/syslog
   

        #============================ /etc/ssl/
        if [[ $(stat -c "%a" "/etc/ssl/") == 755 ]]; then
            stat34="\e[32m$(stat -c "%a" "/etc/ssl/")\e[0m"
            (( score = score + 10 ))
        else
            stat34="\e[31m$(stat -c "%a" "/etc/ssl/")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/ssl/ has permissions $(stat -c "%a" "/etc/ssl/"), it should be 755. Please change the permissions with 'sudo chmod 755 /etc/ssl/'"

        fi
        if [[ $(stat -c "%U:%G" "/etc/ssl/") == "root:root" ]]; then
            owner34="\e[32m$(stat -c "%U:%G" "/etc/ssl/")\e[0m"
            (( score = score + 10 ))
        else
            owner34="\e[31m$(stat -c "%U:%G" "/etc/ssl/")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/ssl/ is owned by $(stat -c "%U:%G" "/etc/ssl/"), it should be root:root. Please change the ownership with 'sudo chown root:root /etc/ssl/'"

        fi

        #=============================== /etc/ssl/private/
        if [[ $(stat -c "%a" "/etc/ssl/private/") == 700 ]]; then
            stat35="\e[32m$(stat -c "%a" "/etc/ssl/private/")\e[0m"
            (( score = score + 10 ))
        else
            stat35="\e[31m$(stat -c "%a" "/etc/ssl/private/")\e[0m"
            (( score = score + 5 )) 
            echo -e "\e[33m#\e[0m Warning: /etc/ssl/private/ has permissions $(stat -c "%a" "/etc/ssl/private/"), it should be 700. Please change the permissions with 'sudo chmod 700 /etc/ssl/private/'"
        fi
        if [[ $(stat -c "%U:%G" "/etc/ssl/private/") == "root:ssl-cert" ]]; then
            owner35="\e[32m$(stat -c "%U:%G" "/etc/ssl/private/")\e[0m"
            (( score = score + 10 ))
        else
            owner35="\e[31m$(stat -c "%U:%G" "/etc/ssl/private/")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/ssl/private/ is owned by $(stat -c "%U:%G" "/etc/ssl/private/"), it should be root:ssl-cert. Please change the ownership with 'sudo chown root:ssl-cert /etc/ssl/private/'"

        fi

        #=============================== /etc/ssl/certs/
        if [[ $(stat -c "%a" "/etc/ssl/certs/") == 755 ]]; then
            stat36="\e[32m$(stat -c "%a" "/etc/ssl/certs/")\e[0m"
            (( score = score + 10 ))
        else
            stat36="\e[31m$(stat -c "%a" "/etc/ssl/certs/")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/ssl/certs/ has permissions $(stat -c "%a" "/etc/ssl/certs/"), it should be 755. Please change the permissions with 'sudo chmod 755 /etc/ssl/certs/'"
        fi  
        if [[ $(stat -c "%U:%G" "/etc/ssl/certs/") == "root:root" ]]; then
            owner36="\e[32m$(stat -c "%U:%G" "/etc/ssl/certs/")\e[0m"
            (( score = score + 10 ))
        else
            owner36="\e[31m$(stat -c "%U:%G" "/etc/ssl/certs/")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/ssl/certs/ is owned by $(stat -c "%U:%G" "/etc/ssl/certs/"), it should be root:root. Please change the ownership with 'sudo chown root:root /etc/ssl/certs/'"

        fi

        #============================  /var/lib/docker/
        #if [[ $(stat -c "%a" "/var/lib/docker/") == 700 ]]; then
        #    stat37="\e[32m$(stat -c "%a" "/var/lib/docker/")\e[0m"
        #    (( score = score + 10 ))
        #else
        #    stat37="\e[31m$(stat -c "%a" "/var/lib/docker/")\e[0m"
        #    (( score = score + 5 ))
        #    echo -e "\e[33m#\e[0m Warning: /var/lib/docker/ has permissions $(stat -c "%a" "/var/lib/docker/"), it should be 700. Please change the permissions with 'sudo chmod 700 /var/lib/docker/'"
        #fi
        #if [[ $(stat -c "%U:%G" "/var/lib/docker/") == "root:root" ]]; then
        #    owner37="\e[32m$(stat -c "%U:%G" "/var/lib/docker/")\e[0m"
        #    (( score = score + 10 ))
        #else
        #    owner37="\e[31m$(stat -c "%U:%G" "/var/lib/docker/")\e[0m"
        #    (( score = score + 5 ))
        #    echo -e "\e[33m#\e[0m Warning: /var/lib/docker/ is owned by $(stat -c "%U:%G" "/var/lib/docker/"), it should be root:root. Please change the ownership with 'sudo chown root:root /var/lib/docker/'"
        #
        #fi

  

        #============================= /etc/nginx/
        if [[ $(stat -c "%a" "/etc/nginx/") == 755 ]]; then
            stat38="\e[33m$(stat -c "%a" "/etc/nginx/")\e[0m"
            (( score = score + 10 ))
            #echo -e "\e[33m#\e[0m Recommended permissions for /etc/nginx/ is 755"
        elif [[ $(stat -c "%a" "/etc/nginx/") == 750 ]]; then
            stat38="\e[32m$(stat -c "%a" "/etc/nginx/")\e[0m"
            (( score = score + 10 ))
        else
            stat38="\e[31m$(stat -c "%a" "/etc/nginx/")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/nginx/ has permissions $(stat -c "%a" "/etc/nginx/"), it should be 755. Please change the permissions with 'sudo chmod 755 /etc/nginx/'"
        fi
        if [[ $(stat -c "%U:%G" "/etc/nginx/") == "root:root" ]]; then
            owner38="\e[32m$(stat -c "%U:%G" "/etc/nginx/")\e[0m"
            (( score = score + 10 ))
        else
            owner38="\e[31m$(stat -c "%U:%G" "/etc/nginx/")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/nginx/ is owned by $(stat -c "%U:%G" "/etc/nginx/"), it should be root:root. Please change the ownership with 'sudo chown root:root /etc/nginx/'"

        fi
        #=============================== /etc/apache2/
        if [[ $(stat -c "%a" "/etc/apache2/") == 755 ]]; then
            stat39="\e[33m$(stat -c "%a" "/etc/apache2/")\e[0m"
            (( score = score + 10 ))
            echo -e "\e[33m#\e[0m Recomended permissions for /etc/apache2/ is 755"
        elif [[ $(stat -c "%a" "/etc/apache2/") == 750 ]]; then
            stat39="\e[32m$(stat -c "%a" "/etc/apache2/")\e[0m"
            (( score = score + 10 ))
        else
            stat39="\e[31m$(stat -c "%a" "/etc/apache2/")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/apache2/ has permissions $(stat -c "%a" "/etc/apache2/"), it should be 755. Please change the permissions with 'sudo chmod 755 /etc/apache2/'"
        fi
        if [[ $(stat -c "%U:%G" "/etc/apache2/") == "root:root" ]]; then
            owner39="\e[32m$(stat -c "%U:%G" "/etc/apache2/")\e[0m"
            (( score = score + 10 ))
        else
            owner39="\e[31m$(stat -c "%U:%G" "/etc/apache2/")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /etc/apache2/ is owned by $(stat -c "%U:%G" "/etc/apache2/"), it should be root:root. Please change the ownership with 'sudo chown root:root /etc/apache2/'"

        fi

        #=============================== /var/www/
        if [[ $(stat -c "%a" "/var/www/") == 755 ]]; then
            stat40="\e[32m$(stat -c "%a" "/var/www/")\e[0m"
            (( score = score + 10 ))
        else
            stat40="\e[31m$(stat -c "%a" "/var/www/")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /var/www/ has permissions $(stat -c "%a" "/var/www/"), it should be 755. Please change the permissions with 'sudo chmod 755 /var/www/'"
        fi
        if [[ $(stat -c "%U:%G" "/var/www/") == "root:root" ]]; then
            owner40="\e[32m$(stat -c "%U:%G" "/var/www/")\e[0m"
            (( score = score + 10 ))
        else
            owner40="\e[31m$(stat -c "%U:%G" "/var/www/")\e[0m"
            (( score = score + 5 ))
            echo -e "\e[33m#\e[0m Warning: /var/www/ is owned by $(stat -c "%U:%G" "/var/www/"), it should be root:root. Please change the ownership with 'sudo chown root:root /var/www/'"

        fi

      


    }
   

    function FILEAUDIT {
        nopass=$(sudo awk -F: '($2 == "") {print $1}' /etc/shadow)
        if [[ -n "$nopass" ]]; then
            user="\e[31mWarning, user without password\e[0m"
            echo -e "\e[33m#\e[0m $nopass dont have password"

        else
            user="\e[32mNo user without password\e[0m"
            (( score = score + 10 ))
        fi


        if [[ $(sudo awk -F: '$3 == 0 {print $1}' /etc/passwd | wc -l) -gt 1 ]]; then
            ruser="\e[31mWarning, more than 1 root user\e[0m"
        else 
            ruser="\e[32mOK\e[0m"
            #(( score = score + 10 ))
        fi

        if [[ $(sudo awk -F: '{print $2}' /etc/shadow | grep -F '$1$' ) ]]; then 
            crypt="\e[31mSAD\e[0m"
            echo -e "\e[33m#\e[0m Warning: Some users have weak password hashing algorithm (MD5)"
        else
            crypt="\e[32mOK\e[0m"
            (( score = score + 10 ))
        fi

        adm=$(who | awk '{print $1}' | uniq )
        if [[ $(grep sudo /etc/group) == "sudo:x:27:$adm" ]]; then
            sudo="\e[32mOnly you\e[0m"
            (( score = score + 10 ))
        elif [[ $(grep sudo /etc/group) =~ "sudo:x:27:$adm" ]]; then
            sudo="\e[33mYou and other users\e[0m"
            echo -e "\e[33m#\e[0m Sudo GROUP: $(grep sudo /etc/group)"
        fi

        if [[ $(grep root /etc/group) == "root:x:0:" ]]; then
            root="\e[32mOnly ROOT\e[0m"
            (( score = score + 10 ))
        else 
            root="\e[33mWarning\e[0m"
            echo -e "\e[33m#\e[0m ROOT GROUP: $(grep root /etc/group)"
        fi
        
        if [[ $(sudo cat /etc/group | grep disk | awk -F: '{print $4}')  == "" ]]; then
            disk="\e[32mOK\e[0m"
            (( score = score + 10 ))
        else
            disk="\e[33mWarning\e[0m"
            echo -e "\e[33m#\e[0m Warning: Users with access to disk group: $(sudo cat /etc/group | grep disk | awk -F: '{print $4}')"
        fi

        if [[ $(sudo cat /etc/sudoers | grep ALL |sed '1d' | awk '{print $1}' | wc -l) -gt 2 ]]; then
            all="\e[31mWarning\e[0m"
            echo -e "\e[33m#\e[0m Warning: Users with ALL access in sudoers file: $(sudo cat /etc/sudoers | grep ALL |sed '1d' | awk '{print $1}')"
        else 
            all="\e[32mOK\e[0m"
            (( score = score + 10 ))
        fi

        if [[ $(cat /etc/fstab | grep /dev) == "" ]]; then
            fstab="\e[32mNo mount /dev/sdx\e[0m"
        else
            fstab="\e[33mUsed /dev/sdx\e[0m"
            echo -e "\e[33m#\e[0m Warning: Your system use /dev/sdx in fstab file. Review it: $(cat /etc/fstab | grep /dev)"
            (( score = score + 10 ))
        fi

        if [[ $(cat /etc/fstab | grep username=*|password=*) == "" ]]; then
            fstab2="\e[32mNo username/password in fstab\e[0m"
            (( score = score + 10 ))
        else
            fstab2="\e[33mFound username/password\e[0m"
            echo -e "\e[33m#\e[0m Warning: Your system use username/password in fstab file. Review it: $(cat /etc/fstab | grep username=*|password=*)"
        fi

        if [[ $(cat /proc/sys/kernel/randomize_va_space) == "2" ]]; then
            aslr="\e[32mEnabled\e[0m"
            (( score = score + 10 ))
        else
            aslr="\e[31mDisabled\e[0m"
            echo -e "\e[33m#\e[0m Warning: ASLR is disabled. Please set /proc/sys/kernel/randomize_va_space = 2"
        fi


        kptr=$(cat /proc/sys/kernel/kptr_restrict)
        if [[ $kptr == "2" ]]; then
            kptr="\e[32m$kptr\e[0m"
            (( score = score + 10 ))
        elif [[ $kptr == "1" ]]; then
            kptr="\e[33m$kptr\e[0m"
        else
            kptr="\e[31mNot restricted\e[0m"
            echo -e "\e[33m#\e[0m Warning: Kernel pointer restriction is not enabled. Please set /proc/sys/kernel/kptr_restrict = 1 or 2"
        fi

        paranoid=$(cat /proc/sys/kernel/perf_event_paranoid)
        if [[ $paranoid == 3 ]]; then
            perf="\e[32mOK\e[0m"

        else
            perf="\e[31mNO\e[0m"
            echo -e "\e[33m#\e[0m Warning: Performance events are not restricted. Please set /proc/sys/kernel/perf_event_paranoid = 3"
        fi

        kernel=$(cat /proc/sys/kernel/dmesg_restrict)
        if [[ $kernel == 1 ]]; then
            klog="\e[32mOK\e[0m"
            (( score = score + 10 ))
        else
            klog="\e[31mNO\e[0m"
            echo -e "\e[33m#\e[0m Warning: Dmesg is not restricted. Please set /proc/sys/kernel/dmesg_restrict = 1"
        fi

        appsec=$(cat /proc/sys/kernel/unprivileged_userns_apparmor_policy)
        if [[ $appsec == "1" ]]; then
            apparmor="\e[32mOK\e[0m"
        else
            apparmor="\e[31mNO\e[0m"
            echo -e "\e[33m#\e[0m Warning: Unprivileged user namespaces are not restricted. Please set /proc/sys/kernel/unprivileged_userns_clone = 1"
        fi

        panic=$(cat /proc/sys/kernel/panic)
        if [[ $panic == "0" ]]; then
            panic="\e[31mNO\e[0m"
            echo -e "\e[33m#\e[0m Recomended '/proc/sys/kernel/panic=10' for restart system"
        else
            panic="\e[32m${panic}Sec\e[0m"
        fi

        
    }

  
    function AV {
        if command -v clamscan &> /dev/null; then
            av="\e[32mInstalled\e[0m"
            (( score = score + 7 ))
        else
            av="\e[31mNot installed\e[0m"
            echo -e "\e[33m#\e[0m ClamAV is not installed, you can install it with 'sudo apt install clamav'"

        fi

        if command -v usbguard &> /dev/null; then
            usb="\e[32mInstalled\e[0m"
            (( score = score + 5 ))
        else
            usb="\e[31mNot installed\e[0m"
            echo -e "\e[33m#\e[0m USB-Guard is not installed, you can install it with 'sudo apt install usbguard'"

        fi

        if command -v rkhunter &> /dev/null; then
            rkh="\e[32mInstalled\e[0m"
            (( score = score + 5 ))
        else
            rkh="\e[31mNot installed\e[0m"
            echo -e "\e[33m#\e[0m RKHunter is not installed, you can install it with 'sudo apt install rkhunter'"

        fi

        if command -v fail2ban &> /dev/null; then
            f2b="\e[32mInstalled\e[0m"
            (( score = score + 5 ))
        else
            f2b="\e[31mNot installed\e[0m"
            echo -e "\e[33m#\e[0m fail2ban is not installed, you can install it with 'sudo apt install fail2ban'"

        fi

        

        if [[ $(systemctl is-active apparmor) == "active" ]]; then
            apparmor="\e[32mActive\e[0m"
            (( score = score + 5 ))
        else
            apparmor="\e[31mInactive\e[0m"
            echo -e "\e[33m#\e[0m AppArmor is not active, you can activate it with 'sudo systemctl start apparmor' and enable it on boot with 'sudo systemctl enable apparmor'"
        fi
        



    }
    
    function DUMP {
        dump1="\e[33mNot found\e[0m"
        dump2="\e[33mNot found\e[0m"
        dump3="\e[33mNot found\e[0m"
        dump5="\e[33mNot found\e[0m"
        dump6="\e[33mNot found\e[0m"
        dump7="\e[33mNot found\e[0m"
        dump8="\e[33mNot found\e[0m"
        dump9="\e[33mNot found\e[0m"
        dump10="\e[33mNot found\e[0m"
        dump11="\e[33mNot found\e[0m"
        dump12="\e[33mNot found\e[0m"

        if [[ -n $located ]]; then
            cd "$located" && pwd &> /dev/null
            if [[ -f "213A.txt" ]]; then
                

                #/boot/grub/grub.cfg
                tmphex=$(sudo md5sum "/boot/grub/grub.cfg" | awk '{print $1}')
                tmp2hex=$(sudo grep /boot/grub/grub.cfg "213A.txt" | awk '{print $1}')
                if [[ "$tmphex" = "$tmp2hex" ]]; then
                    dump1="\e[32mOK\e[0m"
                elif [[ -z $(sudo grep /boot/grub/grub.cfg "213A.txt") ]]; then
                    dump1="\e[33mNot found\e[0m"
                else
                    dump1="\e[31mWARNING\e[0m"
                    echo -e "\e[33m#\e[0m /boot/grub/grub.cfg has been changed. Review it. If this was you, make a new dump."
                fi

                #/etc/fstab
                tmphex=$(sudo md5sum "/etc/fstab" | awk '{print $1}')
                tmp2hex=$(sudo grep fstab "213A.txt" | awk '{print $1}')
                if [[ "$tmphex" = "$tmp2hex" ]]; then
                    dump2="\e[32mOK\e[0m"
                elif [[ -z $(sudo grep /etc/fstab "213A.txt") ]]; then
                    dump2="\e[33mNot found\e[0m"
                else
                    dump2="\e[31mWARNING\e[0m"
                    echo -e "\e[33m#\e[0m /etc/fstab has been changed. Review it. If this was you, make a new dump."
                fi

                #/etc/hosts
                tmphex=$(sudo md5sum "/etc/hosts" | awk '{print $1}')
                tmp2hex=$(sudo grep hosts "213A.txt" | awk '{print $1}')
                if [[ "$tmphex" = "$tmp2hex" ]]; then
                    dump3="\e[32mOK\e[0m"
                elif [[ -z $(sudo grep /etc/hosts "213A.txt") ]]; then
                    dump3="\e[33mNot found\e[0m"
                else
                    dump3="\e[31mWARNING\e[0m"
                    echo -e "\e[33m#\e[0m /etc/hosts has been changed. Review it. If this was you, make a new dump."
                fi


                #/etc/login.defs
                tmphex=$(sudo md5sum "/etc/login.defs" | awk '{print $1}')
                tmp2hex=$(sudo grep login.defs "213A.txt" | awk '{print $1}')
                if [[ "$tmphex" = "$tmp2hex" ]]; then
                    dump5="\e[32mOK\e[0m"
                elif [[ -z $(sudo grep /etc/login.defs "213A.txt") ]]; then
                    dump5="\e[33mNot found\e[0m"
                else
                    dump5="\e[31mWARNING\e[0m"
                    echo -e "\e[33m#\e[0m /etc/login.defs has been changed. Review it. If this was you, make a new dump."
                fi

    

                #/etc/shells
                tmphex=$(sudo md5sum "/etc/shells" | awk '{print $1}')
                tmp2hex=$(sudo grep shells "213A.txt" | awk '{print $1}')
                if [[ "$tmphex" = "$tmp2hex" ]]; then
                    dump6="\e[32mOK\e[0m"
                elif [[ -z $(sudo grep /etc/shells "213A.txt") ]]; then
                    dump6="\e[33mNot found\e[0m"
                else
                    dump6="\e[31mWARNING\e[0m"
                    echo -e "\e[33m#\e[0m /etc/shells has been changed. Review it. If this was you, make a new dump."
                fi

                #/etc/sudoers
                tmphex=$(sudo md5sum "/etc/sudoers" | awk '{print $1}')
                tmp2hex=$(sudo grep sudoers "213A.txt" | awk '{print $1}')
                if [[ "$tmphex" = "$tmp2hex" ]]; then
                    dump7="\e[32mOK\e[0m"
                elif [[ -z $(sudo grep /etc/sudoers "213A.txt") ]]; then
                    dump7="\e[33mNot found\e[0m"
                else
                    dump7="\e[31mWARNING\e[0m"
                    echo -e "\e[33m#\e[0m /etc/sudoers has been changed. Review it. If this was you, make a new dump."
                fi

                #/etc/crontab
                tmphex=$(sudo md5sum "/etc/crontab" | awk '{print $1}')
                tmp2hex=$(sudo grep crontab "213A.txt" | awk '{print $1}')
                if [[ "$tmphex" = "$tmp2hex" ]]; then
                    dump8="\e[32mOK\e[0m"
                elif [[ -z $(sudo grep /etc/crontab "213A.txt") ]]; then
                    dump8="\e[33mNot found\e[0m"
                else
                    dump8="\e[31mWARNING\e[0m"
                    echo -e "\e[33m#\e[0m /etc/crontab has been changed. Review it. If this was you, make a new dump."
                fi

                #/etc/profile
                tmphex=$(sudo md5sum "/etc/profile" | awk '{print $1}')
                tmp2hex=$(sudo grep profile "213A.txt" | awk '{print $1}')
                if [[ "$tmphex" = "$tmp2hex" ]]; then
                    dump9="\e[32mOK\e[0m"
                elif [[ -z $(sudo grep /etc/profile "213A.txt") ]]; then
                    dump9="\e[33mNot found\e[0m"
                else
                    dump9="\e[31mWARNING\e[0m"
                    echo -e "\e[33m#\e[0m /etc/profile has been changed. Review it. If this was you, make a new dump."
                fi


                #/etc/passwd
                tmphex=$(sudo md5sum "/etc/passwd" | awk '{print $1}')
                tmp2hex=$(sudo grep  passwd "213A.txt" | awk '{print $1}')
                if [[ "$tmphex" = "$tmp2hex" ]]; then
                    dump10="\e[32mOK\e[0m"
                elif [[ -z $(sudo grep  shadow "213A.txt") ]]; then
                    dump10="\e[33mNot found\e[0m"
                else
                    dump10="\e[31mWARNING\e[0m"
                    echo -e "\e[33m#\e[0m /etc/passwd has been changed. Review it. If this was you, make a new dump."
                fi




                #/etc/shadow 
                tmphex=$(sudo md5sum "/etc/shadow" | awk '{print $1}')
                tmp2hex=$(sudo grep  shadow "213A.txt" | awk '{print $1}')
                if [[ "$tmphex" = "$tmp2hex" ]]; then
                    dump11="\e[32mOK\e[0m"
                elif ! sudo grep -q "shadow" "213A.txt" 2>/dev/null; then
                    dump11="\e[33mNot found\e[0m"
                else
                    dump11="\e[31mWARNING\e[0m"
                    echo -e "\e[33m#\e[0m /etc/shadow has been changed. Review it. If this was you, make a new dump."

                fi

                #/etc/resolv.conf
                tmphex=$(sudo md5sum "/etc/resolv.conf" | awk '{print $1}')
                tmp2hex=$(sudo grep  resolv.conf "213A.txt" | awk '{print $1}')
                
                if [[ "$tmphex" = "$tmp2hex" ]]; then
                    dump12="\e[32mOK\e[0m"
                elif [[ -z $(sudo grep  resolv.conf "213A.txt") ]]; then
                    dump12="\e[33mNot found\e[0m"
                else
                    dump12="\e[31mWARNING\e[0m"
                    echo -e "\e[33m#\e[0m resolv.conf has been changed. Review it. If this was you, make a new dump."
                fi


                

              

        

                
                

            else
                echo -e "\e[33m#\e[0m Not file 213A.txt"
                echo ""
            fi

            #echo "$located"
        else
            echo -e "\e[33m#\e[0m Please make HEX-Sum enter command: 'mkdir -p reference_scan && cd reference_scan && sudo md5sum /boot/grub/grub.cfg /etc/{fstab,hosts,login.defs,shells,sudoers,crontab,profile,passwd,shadow,resolv.conf} > 213A.txt'"
            echo " It is recommended to save a clean backup in advance, or one that you trust"
            echo ""
            crontab="\e[33mNot found\e[0m"
            resolv="\e[33mNot found\e[0m"
            shadow="\e[33mNot found\e[0m"
            hosts="\e[33mNot found\e[0m"
            passwd="\e[33mNot found\e[0m"
        fi


    }



}

function log {

    if [ -n "$SUDO_USER" ]; then
        user_home=$(eval echo "~$SUDO_USER")
    else
        user_home="$HOME"
    fi
    

    file=$(date +%H-%M-%S)
    mkdir -p "$user_home/scan"
    LOGFILE="$user_home/scan/log${file}.txt"
    

    function strip_colors {
        echo "$1" | sed -E 's/\\e\[[0-9;]*m//g' | sed -E 's/\x1b\[[0-9;]*m//g'
    }
    

    function safe_echo {
        if [[ -z "$1" ]]; then
            echo "N/A"
        else
            strip_colors "$1"
        fi
    }
    
    {
        echo "═══════════════════════════════════════════════════════════"
        echo "              LINUX SECURITY AUDIT REPORT"
        echo "═══════════════════════════════════════════════════════════"
        echo "DATE: $(date '+%Y-%m-%d %H:%M:%S %Z')"
        echo "HOST: $(hostname)"
        echo ""
        
        # ============================================================
        echo "───────────────────────────────────────────────────────────"
        echo "GENERAL SYSTEM INFORMATION"
        echo "───────────────────────────────────────────────────────────"
        echo "OS_VERSION          : $(safe_echo "$os")"
        echo "OS_FAMILY           : $(safe_echo "$IDLIKE")"
        echo "OS_ID               : $(safe_echo "$ID")"
        echo "OS_RELEASE          : $(safe_echo "$VERSION")"
        echo "OS_TYPE             : $(safe_echo "$type")"
        echo "INTERNET            : $(safe_echo "$net")"
        echo "DATE_STATUS         : $(safe_echo "$act")"
        echo "UFW                 : $(safe_echo "$ufw")"
        if [[ "$ufw" == *Installed* ]]; then
            echo "UFW_STATUS          : $(safe_echo "$ufw_status")"
        fi
        echo "VPN                 : $(safe_echo "$vpn")"
        echo "PORT_LISTEN         : $(safe_echo "$ports")"
        echo "UPDATES             : $(safe_echo "$update")"
        echo ""
        
        # ============================================================
        echo "───────────────────────────────────────────────────────────"
        echo "HARDWARE & RESOURCES"
        echo "───────────────────────────────────────────────────────────"
        echo "CPU_MODEL           : $(safe_echo "$model")"
        echo "NX/XD               : $(safe_echo "$nx")"
        echo "SMEP                : $(safe_echo "$smep")"
        echo "SMAP                : $(safe_echo "$smap")"
        echo "AVX                 : $(safe_echo "$AVX")"
        echo "AVX512              : $(safe_echo "$AVX512")"
        echo "SSE4_2              : $(safe_echo "$sse")"
        echo "AES                 : $(safe_echo "$aes")"
        echo "SHA                 : $(safe_echo "$sha")"
        echo "FREE_SPACE          : $(safe_echo "$free2") (${free%?}/100%)"
        echo "FREE_MEMORY         : $(safe_echo "$mems") (${memfree} MB)"
        echo ""
        
        # ============================================================
        echo "───────────────────────────────────────────────────────────"
        echo "DNS SERVERS"
        echo "───────────────────────────────────────────────────────────"
        if [ ${#arrdns[@]} -gt 0 ]; then
            for dns in "${arrdns[@]}"; do
                echo "DNS_SERVER          : $(safe_echo "$dns")"
            done
        else
            echo "DNS_SERVER          : No DNS servers defined"
        fi
        echo ""
        
        # ============================================================
        echo "───────────────────────────────────────────────────────────"
        echo "FILE PERMISSIONS & OWNERSHIP"
        echo "───────────────────────────────────────────────────────────"
        printf "%-25s %-12s %-15s\n" "PATH" "PERMISSIONS" "OWNER"
        printf "%-25s %-12s %-15s\n" "/home" "$(safe_echo "$stat1")" "$(safe_echo "$owner1")"
        printf "%-25s %-12s %-15s\n" "/root" "$(safe_echo "$stat2")" "$(safe_echo "$owner2")"
        printf "%-25s %-12s %-15s\n" "/boot" "$(safe_echo "$stat3")" "$(safe_echo "$owner3")"
        printf "%-25s %-12s %-15s\n" "/boot/grub/grub.cfg" "$(safe_echo "$stat4")" "$(safe_echo "$owner4")"
        printf "%-25s %-12s %-15s\n" "/etc/fstab" "$(safe_echo "$stat5")" "$(safe_echo "$owner5")"
        printf "%-25s %-12s %-15s\n" "/etc/hosts" "$(safe_echo "$stat6")" "$(safe_echo "$owner6")"
        printf "%-25s %-12s %-15s\n" "/etc/passwd" "$(safe_echo "$stat7")" "$(safe_echo "$owner7")"
        printf "%-25s %-12s %-15s\n" "/etc/shadow" "$(safe_echo "$stat8")" "$(safe_echo "$owner8")"
        printf "%-25s %-12s %-15s\n" "/etc/group" "$(safe_echo "$stat9")" "$(safe_echo "$owner9")"
        printf "%-25s %-12s %-15s\n" "/etc/gshadow" "$(safe_echo "$stat10")" "$(safe_echo "$owner10")"
        printf "%-25s %-12s %-15s\n" "/etc/login.defs" "$(safe_echo "$stat11")" "$(safe_echo "$owner11")"
        printf "%-25s %-12s %-15s\n" "/etc/shells" "$(safe_echo "$stat12")" "$(safe_echo "$owner12")"
        printf "%-25s %-12s %-15s\n" "/etc/sudoers" "$(safe_echo "$stat13")" "$(safe_echo "$owner13")"
        printf "%-25s %-12s %-15s\n" "/etc/sudoers.d/" "$(safe_echo "$stat14")" "$(safe_echo "$owner14")"
        printf "%-25s %-12s %-15s\n" "/etc/pam.d/" "$(safe_echo "$stat15")" "$(safe_echo "$owner15")"
        printf "%-25s %-12s %-15s\n" "/etc/security/" "$(safe_echo "$stat16")" "$(safe_echo "$owner16")"
        printf "%-25s %-12s %-15s\n" "/etc/ssh/sshd_config" "$(safe_echo "$stat17")" "$(safe_echo "$owner17")"
        printf "%-25s %-12s %-15s\n" "/etc/ssh/ssh_config" "$(safe_echo "$stat18")" "$(safe_echo "$owner18")"
        printf "%-25s %-12s %-15s\n" "/root/.ssh/" "$(safe_echo "$stat19")" "$(safe_echo "$owner19")"
        printf "%-25s %-12s %-15s\n" "/etc/profile" "$(safe_echo "$stat21")" "$(safe_echo "$owner21")"
        printf "%-25s %-12s %-15s\n" "/etc/bash.bashrc" "$(safe_echo "$stat22")" "$(safe_echo "$owner22")"
        printf "%-25s %-12s %-15s\n" "/etc/crontab" "$(safe_echo "$stat23")" "$(safe_echo "$owner23")"
        printf "%-25s %-12s %-15s\n" "/etc/cron.d/" "$(safe_echo "$stat24")" "$(safe_echo "$owner24")"
        printf "%-25s %-12s %-15s\n" "/etc/cron.daily/" "$(safe_echo "$stat25")" "$(safe_echo "$owner25")"
        printf "%-25s %-12s %-15s\n" "/etc/cron.hourly/" "$(safe_echo "$stat26")" "$(safe_echo "$owner26")"
        printf "%-25s %-12s %-15s\n" "/etc/cron.monthly/" "$(safe_echo "$stat27")" "$(safe_echo "$owner27")"
        printf "%-25s %-12s %-15s\n" "/etc/cron.weekly/" "$(safe_echo "$stat28")" "$(safe_echo "$owner28")"
        printf "%-25s %-12s %-15s\n" "/etc/systemd/" "$(safe_echo "$stat30")" "$(safe_echo "$owner30")"
        printf "%-25s %-12s %-15s\n" "/usr/lib/systemd/" "$(safe_echo "$stat31")" "$(safe_echo "$owner31")"
        printf "%-25s %-12s %-15s\n" "/lib/systemd/" "$(safe_echo "$stat32")" "$(safe_echo "$owner32")"
        printf "%-25s %-12s %-15s\n" "/etc/ssl/" "$(safe_echo "$stat34")" "$(safe_echo "$owner34")"
        printf "%-25s %-12s %-15s\n" "/etc/ssl/private/" "$(safe_echo "$stat35")" "$(safe_echo "$owner35")"
        printf "%-25s %-12s %-15s\n" "/etc/ssl/certs/" "$(safe_echo "$stat36")" "$(safe_echo "$owner36")"
        printf "%-25s %-12s %-15s\n" "/etc/nginx/" "$(safe_echo "$stat38")" "$(safe_echo "$owner38")"
        printf "%-25s %-12s %-15s\n" "/etc/apache2/" "$(safe_echo "$stat39")" "$(safe_echo "$owner39")"
        printf "%-25s %-12s %-15s\n" "/var/www/" "$(safe_echo "$stat40")" "$(safe_echo "$owner40")"
        echo ""
        
        # ============================================================
        echo "───────────────────────────────────────────────────────────"
        echo "SYSTEM AUDIT"
        echo "───────────────────────────────────────────────────────────"
        echo "USERS_WITHOUT_PASS  : $(safe_echo "$user")"
        echo "OTHER_ROOT_USERS    : $(safe_echo "$ruser")"
        echo "PASSWORD_CRYPT      : $(safe_echo "$crypt")"
        echo "SUDO_GROUP          : $(safe_echo "$sudo")"
        echo "ROOT_GROUP          : $(safe_echo "$root")"
        echo "DISK_GROUP          : $(safe_echo "$disk")"
        echo "ALL_ACCESS_USERS    : $(safe_echo "$all")"
        echo "FSTAB_DEV           : $(safe_echo "$fstab")"
        echo "FSTAB_CREDENTIALS   : $(safe_echo "$fstab2")"
        echo "ASLR                : $(safe_echo "$aslr")"
        echo "KPTR_RESTRICT       : $(safe_echo "$kptr")"
        echo "PERF_EVENT_PARANOID : $(safe_echo "$perf")"
        echo "DMESG_RESTRICT      : $(safe_echo "$klog")"
        echo "APPARMOR_RESTRICT   : $(safe_echo "$apparmor")"
        echo "PANIC_TIMEOUT       : $(safe_echo "$panic")"
        echo ""
        
        # ============================================================
        echo "───────────────────────────────────────────────────────────"
        echo "ANTI-VIRUS & SECURITY TOOLS"
        echo "───────────────────────────────────────────────────────────"
        echo "CLAMAV              : $(safe_echo "$av")"
        echo "USBGUARD            : $(safe_echo "$usb")"
        echo "RKHUNTER            : $(safe_echo "$rkh")"
        echo "APPARMOR            : $(safe_echo "$apparmor")"
        echo "FAIL2BAN            : $(safe_echo "$f2b")"
        echo "CLAMAV_SCAN_STATUS  : $(safe_echo "$scanav")"
        echo ""
        
        # ============================================================
        echo "───────────────────────────────────────────────────────────"
        echo "HEX DUMP INTEGRITY CHECK"
        echo "───────────────────────────────────────────────────────────"
        printf "%-25s %-15s\n" "FILE" "STATUS"
        printf "%-25s %-15s\n" "/boot/grub/grub.cfg" "$(safe_echo "$dump1")"
        printf "%-25s %-15s\n" "/etc/fstab" "$(safe_echo "$dump2")"
        printf "%-25s %-15s\n" "/etc/hosts" "$(safe_echo "$dump3")"
        printf "%-25s %-15s\n" "/etc/login.defs" "$(safe_echo "$dump5")"
        printf "%-25s %-15s\n" "/etc/shells" "$(safe_echo "$dump6")"
        printf "%-25s %-15s\n" "/etc/sudoers" "$(safe_echo "$dump7")"
        printf "%-25s %-15s\n" "/etc/crontab" "$(safe_echo "$dump8")"
        printf "%-25s %-15s\n" "/etc/profile" "$(safe_echo "$dump9")"
        printf "%-25s %-15s\n" "/etc/passwd" "$(safe_echo "$dump10")"
        printf "%-25s %-15s\n" "/etc/shadow" "$(safe_echo "$dump11")"
        printf "%-25s %-15s\n" "/etc/resolv.conf" "$(safe_echo "$dump12")"
        echo ""
        
        # ============================================================
        echo "───────────────────────────────────────────────────────────"
        echo "SECURITY SCORE"
        echo "───────────────────────────────────────────────────────────"
        echo "TOTAL_SCORE         : $score / 100"
        
        echo ""
        
        echo "═══════════════════════════════════════════════════════════"
        echo "                    END OF REPORT"
        echo "═══════════════════════════════════════════════════════════"
        
    } >> "$LOGFILE"
    
    echo "[+] Audit log saved: $LOGFILE"
}





if [[ "$os" =~ [Ll]inux ]]; then
    Linux
    echo -e "--------------------------------------------"
    echo -e "[+]               \033[1mPC Stat\033[0m                  |"
    echo -e "--------------------------------------------"
    PC
    echo ""
    echo -e "CPU: \t \t [\e[35m$model\e[0m]"
    echo -e "NX: \t \t [$nx]"
    echo -e "SMEP: \t \t [$smep]"
    echo -e "SMAP: \t \t [$smap]"
    echo -e "AVX: \t \t [$AVX]"
    echo -e "AVX512: \t [$AVX512]"
    echo -e "SSE4_2: \t [$sse]"
    echo -e "AES: \t \t [$aes]"
    echo -e "SHA: \t \t [$sha]"
    echo -e "Free space: \t [$free2] ${free%?}/100%"
    echo -e "Free mem: \t [$mems] $memfree MB"
    echo ""


    echo -e "--------------------------------------------"
    echo -e "[+]              \033[1mInternet\033[0m                  |"
    echo -e "--------------------------------------------"
    net
    echo ""
    echo -e "Internet: \t [$net]"
    echo -e "Date: \t \t [$act]" 
    echo -e "UFW: \t \t [$ufw]" 
    if [[ "$ufw" == *Installed* ]]; then
        ufw_status=$(sudo ufw status | grep -i 'Status:' | awk '{print $2}')
        echo -e " \t \t Status: [$ufw_status]" 
        if [[ "$ufw_status" == "active" ]]; then
            (( score = score + 7 ))
        fi
    fi
    echo -e "VPN: \t \t [$vpn]"
    echo -e "Port listen: \t [$ports]"
    printf "DNS:  \t \t %s\n" "${arrdns[@]}"
    echo -e "Updates: \t [$update]" 
    echo ""

    echo -e "--------------------------------------------"
    echo -e "[+]         \033[1mSecurity File Audit\033[0m            |"
    echo -e "--------------------------------------------"
    RWXAUDIT
    echo ""
    echo " PATH                   RWX      Owner"
    echo -e " /home               \t[$stat1] \t [$owner1]"  
    echo -e " /root               \t[$stat2] \t [$owner2]"  
    echo -e " /boot               \t[$stat3] \t [$owner3]"  
    echo -e " /boot/grub/grub.cfg \t[$stat4] \t [$owner4]" 
    echo -e " /etc/fstab          \t[$stat5] \t [$owner5]" 
    echo -e " /etc/hosts          \t[$stat6] \t [$owner6]" 
    echo -e " /etc/passwd         \t[$stat7] \t [$owner7]"
    echo -e " /etc/shadow         \t[$stat8] \t [$owner8]"
    echo -e " /etc/group          \t[$stat9] \t [$owner9]"
    echo -e " /etc/gshadow        \t[$stat10] \t [$owner10]"
    echo -e " /etc/login.defs     \t[$stat11] \t [$owner11]"
    echo -e " /etc/shells         \t[$stat12] \t [$owner12]"
    echo -e " /etc/sudoers        \t[$stat13] \t [$owner13]"
    echo -e " /etc/sudoers.d/     \t[$stat14] \t [$owner14]"
    echo -e " /etc/pam.d/         \t[$stat15] \t [$owner15]"
    echo -e " /etc/security/      \t[$stat16] \t [$owner16]"
    echo -e " /etc/ssh/sshd_config\t[$stat17] \t [$owner17]"
    echo -e " /etc/ssh/ssh_config \t[$stat18] \t [$owner18]"
    echo -e " /root/.ssh/         \t[$stat19] \t [$owner19]"
    #echo -e " /home/*/.ssh/       \t[$stat20] \t [$owner20] \t [$dump20]"
    echo -e " /etc/profile        \t[$stat21] \t [$owner21]"
    echo -e " /etc/bash.bashrc    \t[$stat22] \t [$owner22]"
    echo -e " /etc/crontab        \t[$stat23] \t [$owner23]"
    echo -e " /etc/cron.d/        \t[$stat24] \t [$owner24]"
    echo -e " /etc/cron.daily/    \t[$stat25] \t [$owner25]"
    echo -e " /etc/cron.hourly/   \t[$stat26] \t [$owner26]"
    echo -e " /etc/cron.monthly/  \t[$stat27] \t [$owner27]"
    echo -e " /etc/cron.weekly/   \t[$stat28] \t [$owner28]"
    #echo -e " /var/log/cron       \t[$stat29] \t [$owner29] \t [$dump29]"
    echo -e " /etc/systemd/       \t[$stat30] \t [$owner30]"
    echo -e " /usr/lib/systemd/   \t[$stat31] \t [$owner31]"
    echo -e " /lib/systemd/       \t[$stat32] \t [$owner32]"
    #echo -e " /var/log/syslog     \t[$stat33] \t [$owner33] \t [$dump33]"
    echo -e " /etc/ssl/           \t[$stat34] \t [$owner34]"
    echo -e " /etc/ssl/private/   \t[$stat35] \t [$owner35]"
    echo -e " /etc/ssl/certs/     \t[$stat36] \t [$owner36]"
    #echo -e " /var/lib/docker/    \t[$stat37] \t [$owner37] \t [$dump37]"
    echo -e " /etc/nginx/         \t[$stat38] \t [$owner38]"
    echo -e " /etc/apache2/       \t[$stat39] \t [$owner39]"
    echo -e " /var/www/           \t[$stat40] \t [$owner40]"
    echo ""

    echo -e "--------------------------------------------"
    echo -e "[+]             \033[1mSystem Audit\033[0m               |"
    echo -e "--------------------------------------------"
    FILEAUDIT
    echo ""
    echo -e "users without pass: \t [$user]"
    echo -e "Other Root: \t \t [$ruser]"
    echo -e "Pass crypt: \t \t [$crypt]"
    echo -e "Sudo GROUP: \t \t [$sudo]"
    echo -e "ROOT GROUP: \t \t [$root]"
    echo -e "DISK GROUP: \t \t [$disk]"
    echo -e "ALL Access users: \t [$all]"
    #echo -e "Security disk fstab: \t [$secfstab]"
    echo -e "/dev/sdx: \t \t [$fstab]"
    echo -e "Name or Pass in fstab: \t [$fstab2]"
    echo -e "ASLR: \t \t \t [$aslr]"
    echo -e "ret2usr: \t \t [$kptr]"
    echo -e "Restricted syscalls: \t [$perf]"
    echo -e "Kernel log restricted: \t [$klog]"
    echo -e "AppArmor restricted: \t [$apparmor]"
    echo -e "Restart Panic: \t \t [$panic]"



    echo ""

 

    echo -e "--------------------------------------------"
    echo -e "[+]                 \033[1mAV\033[0m                     |"
    echo -e "--------------------------------------------"
    AV
    echo ""
    echo -e "Anti-Virus: \t [$av]" 
    echo -e "USB-Guard: \t [$usb]" 
    echo -e "RKHunter: \t [$rkh]" 
    echo -e "APPArmor: \t [$apparmor]" 
    echo -e "fail2ban: \t [$f2b]"
    echo ""

 

    echo -e "--------------------------------------------"
    echo -e "[+]             \033[1mDump Analys\033[0m                |"
    echo -e "--------------------------------------------"
    DUMP
    echo ""
    echo -e "HEX /boot/grub/grub.cfg\t [$dump1]"
    echo -e "HEX /etc/fstab  \t [$dump2]"
    echo -e "HEX /etc/hosts  \t [$dump3]"
    echo -e "HEX /etc/login.defs \t [$dump5]"
    echo -e "HEX /etc/shells \t [$dump6]"
    echo -e "HEX /etc/sudoers \t [$dump7]"
    echo -e "HEX /etc/crontab \t [$dump8]"
    echo -e "HEX /etc/profile \t [$dump9]"
    echo -e "HEX /etc/passwd \t [$dump10]"
    echo -e "HEX /etc/shadow \t [$dump11]"
    echo -e "HEX /etc/resolv.conf \t [$dump12]"
    echo ""

    #echo -e "Total score: \t $score/100"
    if [[ "$arg1" == "l" ]]; then
        log
    fi
    if [[ -f tmpscan.txt ]];then
        rm tmpscan.txt
    fi
    sudo updatedb
fi
