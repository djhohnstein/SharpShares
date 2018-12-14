# Sharp Shares

## Description

Quick and dirty binary to list network share information from all machines in the current domain and if they're readable. Can also translate all computer names to ip addresses.

## Usage

`SharpShares.exe ips` - Output computer information in the format of `$HOSTNAME: $IP`

`SharpShares.exe shares` - Query each computer in the domain for network shares and if they're readable by the current user.

## Example

```
> .\SharpShares.exe shares

Shares for WIN-E9V6E2B5IFM:
        [--- Unreadable Shares ---]
		IPC
	[--- Listable Shares --- ]
		ADMIN$
		C$
		NETLOGON
		SYSVOL
```

```
> .\SharpShares.exe ips
WIN-E9V6E2B5IFM: 192.168.193.208
```
