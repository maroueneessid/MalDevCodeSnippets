
## User Mode Rootkit ##

- **Rtkit** : monitors for process creation using WMI , inject GoDark.dll upon detecting blacklisted processes. Requires Admin privileges.
- **goDark** : DLL using the Microsoft Detours library to hook *NtQueryProcessInformation* and hide a specified process.
