# MikroTik ltAP LTE6 (RouterOS 7): Hotspot settings the portal needs. Review the variables, then paste
# into the terminal (or /import). Names of your existing hotspot objects may differ: check with
#   /ip hotspot print ; /ip hotspot profile print
:local portal "10.20.0.31"
:local radius "10.20.0.21"
:local secret "CHANGE-ME-same-as-clients.conf-in-LXC-102"
:local hsprofile "hsprof1"
:local sharedMember 4

# 1. RADIUS for the hotspot. PAP is required: the portal's one-time token travels as the password.
/radius add service=hotspot address=$radius secret=$secret timeout=3s comment="media portal"
/ip hotspot profile set [find name=$hsprofile] use-radius=yes radius-accounting=yes \
    radius-interim-update=5m login-by=http-pap nas-port-type=wireless-802.11

# 2. User profiles: names must match the Mikrotik-Group the portal returns (guest/member/internet/admin).
#    shared-users > 1 lets one account be used on several devices (phone + laptop).
/ip hotspot user profile
add name=guest    shared-users=1
add name=member   shared-users=$sharedMember
add name=internet shared-users=$sharedMember
add name=admin    shared-users=$sharedMember

# 3. Before login, clients may reach only the portal (HTTP login, sign-up and /ca pages).
/ip hotspot walled-garden ip add dst-address=$portal action=accept comment="media portal"

# 4. Let the router accept the portal's REST disconnect calls (Sessions page, Suspend).
#    Create the API user with only the rights it needs, then put its password in portal.env (ROUTER_PASS).
/user group add name=portal-kick policy=read,write,api,rest-api
/user add name=portal group=portal-kick password="CHANGE-ME" address=$portal/32
/ip service set www-ssl disabled=no
# ROUTER_URL=https://10.20.0.1 (use the router's LAN address)

# 5. Upload deploy/hotspot-login.html to the router as hotspot/login.html (Files menu, or ftp/scp).
#    It sends unauthenticated clients to the portal with their MAC address.
