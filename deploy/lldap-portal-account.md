# LLDAP: rights the portal account needs

The portal's `portal` account creates users, sets passwords, changes group membership and deletes users.
In the LLDAP web page (http://10.20.0.21:17170) check, as the LLDAP admin:

1. Users > `portal` > Groups: it must be in **lldap_admin** (user and group management through GraphQL
   needs it; `lldap_password_manager` alone cannot create users or change groups).
2. Groups: `media_members`, `media_internet` and `media_admin` exist (the portal looks them up by name).
3. The admin accounts you want for the portal's /admin pages are in `media_admin`.

Quick check from LXC 103 (replace the password):

    curl -s -X POST http://10.20.0.21:17170/auth/simple/login \
      -H 'Content-Type: application/json' -d '{"username":"portal","password":"..."}'

A JSON reply with a `token` means the account and password are right.
