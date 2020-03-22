#!/bin/bash

convert_rules () {
    local backend_config=$1
    shift
    local config=$1
    shift
    local path=("$@")
    for rule in "${path[@]}"
    do
        echo "Processing" $rule
	filename=$(basename -- "$rule")
	name_no_extension="${filename%.*}"
	python ./tools/sigmac $rule -t es-rule --backend-config ./tools/config/backends/$backend_config -c ./tools/config/$config > ./es-rules-output/$name_no_extension.ndjson
    done
}

# Create output directory needed
mkdir es-rules-output
# Declare rule paths which
builtin_rules=(./rules/windows/builtin/*)
malware_rules=(./rules/windows/malware/*)
process_rules=(./rules/windows/process_creation/*)
sysmon_rules=(./rules/windows/sysmon/*)
powershell_rules=(./rules/windows/powershell/*)
auditd_rules=(./rules/linux/auditd/*)
echo "Processing Windows Builtin rules"
convert_rules "backend-config-winlogbeat.yml" "winlogbeat-modules-enabled.yml" "${builtin_rules[@]}"
echo "Processing Windows Malware rules"
convert_rules "backend-config-winlogbeat.yml" "winlogbeat-modules-enabled.yml" "${malware_rules[@]}"
echo "Processing Windows Process Create rules"
convert_rules "backend-config-winlogbeat.yml" "winlogbeat-modules-enabled.yml" "${process_rules[@]}"
#echo "Processing Windows Powershell rules"
#convert_rules "backend-config-winlogbeat.yml" "winlogbeat-modules-enabled.yml" "${powershell_rules[@]}"
echo "Processing Windows Sysmon rules"
convert_rules "backend-config-winlogbeat.yml" "winlogbeat-modules-enabled.yml" "${sysmon_rules[@]}"
echo "Processing Linux Auditd rules"
convert_rules "backend-config-auditbeat.yml" "auditbeat.yml" "${auditd_rules[@]}"
