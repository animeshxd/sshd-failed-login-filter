import re
import sys

filename = sys.argv[1]

if not filename:
    exit(1)

ip_addresses = set()
regex = re.compile(r'(([0-9]{1,3}\.){3}[0-9]{1,3})', flags=re.MULTILINE)

whitelists = {
    
}

hosts_deny = '/etc/hosts.deny'

def get_ip_addresses(filename: str):
    ip_addresses = set()
    try:
        with open(filename) as f:
            for line in f.readlines():
                match = regex.search(line)
                if not match:
                    continue
                ip = match.group(0)
                if ip in whitelists:
                    sys.stderr.write(f"[INFO] Whitelisted IP found, ignoring...\n")
                    continue
                ip_addresses.add(ip)
    except FileNotFoundError:
        sys.stderr.write(f"[WARNING] {filename} not found\n")
    except Exception as e:
        sys.stderr.write(f"[ERROR] {e}")
    return ip_addresses


ip_addresses.update(get_ip_addresses(hosts_deny))
sys.stderr.write(f"[INFO] Number of existing IP addresses: {len(ip_addresses)} (from {hosts_deny})\n")

ip_addresses.update(get_ip_addresses(filename))
sys.stderr.write(f"[INFO] Number of new IP addresses: {len(ip_addresses)} (from {filename})\n")
    
sys.stdout.write('\n'.join(f'sshd: {i}' for i in ip_addresses))
print()
